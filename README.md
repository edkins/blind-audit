# TEE Hackathon

A web application running on AWS with Nitro Enclaves for trusted execution, Cognito authentication via ALB, and automated deployments via GitHub Actions.

## Deployment workflow (AWS)

```
You (one time):
  terraform apply  →  Creates VPC, ALB, Cognito, EC2, etc.
                      State saved locally in terraform.tfstate

GitHub Actions (on every push):
  docker build     →  Build containers
  docker push      →  Push to ECR
  ssm send-command →  Tell EC2 to pull & restart
```

Note: the `terraform apply` uses *local state* so you'll need to change this if updating the infrastructure between machines/users. GitHub itself does not make use of terraform, only ssm.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           Internet                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Load Balancer                    │
│                    (Public Subnets, HTTPS)                      │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │                  Cognito Authentication                  │  │
│   │            (Redirects unauthenticated users)             │  │
│   └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼ (authenticated requests only)
┌─────────────────────────────────────────────────────────────────┐
│                        Private Subnet                           │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │                     EC2 Instance                         │  │
│   │                                                          │  │
│   │   ┌─────────────────┐      vsock      ┌───────────────┐  │  │
│   │   │   Web Server    │◄───────────────►│  Nitro        │  │  │
│   │   │   (Docker)      │                 │  Enclave      │  │  │
│   │   │   Port 8000     │                 │  (Isolated)   │  │  │
│   │   └─────────────────┘                 └───────────────┘  │  │
│   │                                                          │  │
│   └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- [AWS account](https://signin.aws.amazon.com/signup?request_type=register)
- [Terraform >= 1.0](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
- [AWS CLI configured locally](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- GitHub repository (fork this one)
- A domain name (Route 53 registered, or elsewhere with ability to update nameservers)

## Setup

### 1. Bootstrap AWS ↔ GitHub trust

This creates the OIDC provider and IAM role that allows GitHub Actions to deploy to your AWS account without long-lived credentials.

You will first need to set up an iam user for terraform to use (an admin user will work fine, or you can use the slightly more locked down one as shown in `infra/terraform-user-policy.json`). Set up the correct access/secret key with `aws configure` before starting.

You can also check which aws iam user is configured locally with the command `aws sts get-caller-identity`.

```bash
cd infra/bootstrap

terraform init
terraform apply -var="github_repo=YOUR_USERNAME/YOUR_REPO"
```

Save the `github_actions_role_arn` output - you'll need it for GitHub configuration.

### 2. Configure your domain

Copy the example variables file:

```bash
cd infra/main
cp example.tfvars terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
# Your domain
domain_name = "yourdomain.com"

# Optional: use a subdomain (e.g., "app" for app.yourdomain.com)
app_subdomain = ""

# If your domain is registered in Route 53, set this to false
# If registered elsewhere (GoDaddy, Namecheap, etc.), set to true
create_hosted_zone = false
```

### 3. Deploy infrastructure

```bash
terraform init
terraform apply
```

This creates:
- VPC with public/private subnets
- NAT Gateway and VPC endpoints for SSM
- Route 53 DNS records
- ACM certificate (automatically validated via DNS)
- Cognito User Pool with hosted UI
- Application Load Balancer with Cognito authentication
- ECR repositories for container images
- EC2 instance with Nitro Enclave support

**If you set `create_hosted_zone = true`**: Terraform will output nameservers. Update your domain registrar to use these nameservers, then wait for propagation (can take up to 48 hours, usually much faster).

Note the outputs, especially:
- `instance_id` - for GitHub configuration
- `app_url` - to access your application
- `cognito_domain` - to manage users

### 3. Configure GitHub

Go to your repository → Settings → Secrets and variables → Actions

**Secrets:**
| Name | Value |
|------|-------|
| `AWS_ROLE_ARN` | The github_actions_role_arn ARN from bootstrap output |
| `INSTANCE_ID` | The instance ID from main output |

**Variables:**
| Name | Value |
|------|-------|
| `AWS_REGION` | `us-east-2` (or your region) |
| `PROJECT_NAME` | `blind-audit` (or what was configured in terraform.tfvars) |

### 4. Create a Cognito user

Go to the AWS Console → Cognito → User Pools → your pool → Users → Create user

Or use the CLI:
```bash
aws cognito-idp admin-create-user \
  --user-pool-id YOUR_POOL_ID \
  --username your@email.com \
  --temporary-password TempPass123! \
  --user-attributes Name=email,Value=your@email.com Name=email_verified,Value=true
```

### 5. Deploy!

Push to `main` and GitHub Actions will:
1. Build the enclave and webserver Docker images
2. Push them to ECR
3. Deploy to the EC2 instance via SSM

Or trigger manually from Actions → Deploy → Run workflow (with optional debug mode).

## Development

### Local testing

The webserver can run locally (without the enclave):

```bash
cd webserver
pip install -r requirements.txt
ENCLAVE_CID=16 python main.py
```

### Connecting to the instance

```bash
aws ssm start-session --target INSTANCE_ID --region us-east-2
```

### Viewing enclave logs (debug mode only)

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

### Manual deployment

SSH/SSM into the instance and run:
```bash
export IMAGE_TAG=latest
export DEBUG_MODE=true
/home/ec2-user/deploy.sh
```

## Project structure

```
.
├── .github/workflows/deploy.yml   # CI/CD pipeline
├── infra/
│   ├── bootstrap/                 # One-time OIDC setup
│   │   ├── main.tf
│   │   └── oidc.tf
│   └── main/                      # Main infrastructure
│       ├── main.tf
│       ├── variables.tf
│       ├── example.tfvars         # Copy to terraform.tfvars
│       ├── vpc.tf
│       ├── dns.tf                 # Route 53 + ACM certificate
│       ├── cognito.tf
│       ├── alb.tf
│       ├── ecr.tf
│       ├── iam.tf
│       ├── ec2.tf
│       ├── user_data.sh
│       └── outputs.tf
├── enclave/                       # Enclave application
│   ├── main.py
│   └── requirements.txt
├── webserver/                     # Web server application
│   ├── main.py
│   └── requirements.txt
├── Dockerfile.enclave
├── Dockerfile.webserver
└── README.md
```

## Security notes

- The EC2 instance has no public IP and is only accessible via the ALB or SSM
- All traffic to the ALB requires Cognito authentication (except `/health`)
- The enclave runs in complete isolation with no network or disk access
- Communication between webserver and enclave is via vsock only
- Debug mode should be disabled for production (attestation will indicate debug)

## Troubleshooting

**Deployment fails with "Enclave memory/CPU allocation failed"**
- The instance type might not have enough resources
- Check that the allocator is running: `systemctl status nitro-enclaves-allocator`
- Check allocation: `cat /etc/nitro_enclaves/allocator.yaml`

**Can't connect to the app**
- Check the target group health in the EC2 console
- Ensure the webserver is running: `docker ps`
- Check logs: `docker logs webserver`

**Cognito login redirects in a loop**
- Verify the callback URL matches: `https://YOUR_ALB_DNS/oauth2/idpresponse`
- Check the Cognito app client settings

## License

MIT
