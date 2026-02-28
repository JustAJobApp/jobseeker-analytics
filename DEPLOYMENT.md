# Deployment Runbook

This document provides comprehensive procedures for deploying, maintaining, and recovering the JustAJobApp application. It serves as the operational runbook for the production environment.

## Table of Contents

- [Deployment Architecture](#deployment-architecture)
- [Automated Deployment](#automated-deployment)
- [Manual Deployment](#manual-deployment)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Post-Deployment Validation](#post-deployment-validation)
- [Rollback Procedures](#rollback-procedures)
- [Backup and Restore](#backup-and-restore)
- [Disaster Recovery](#disaster-recovery)
- [Secrets Management](#secrets-management)
- [Troubleshooting](#troubleshooting)

---

## Deployment Architecture

### Infrastructure Overview

| Component | Technology | Hosting |
|-----------|------------|---------|
| Frontend | Next.js 16+ | AWS Lightsail Container Service (`jaja-frontend`) |
| Backend | FastAPI/Python 3.11 | AWS Lightsail Container Service (`jaja-backend`) |
| Database | PostgreSQL 13 | AWS Lightsail Managed Database |
| CI/CD | GitHub Actions | GitHub-hosted runners |

### Service Endpoints

| Service | Container Port | Public Port | Health Check Path |
|---------|---------------|-------------|-------------------|
| Frontend | 3000 | 80 (HTTPS) | `/` |
| Backend | 8000 | 80 (HTTPS) | `/` |

### Deployment Flow

```
Push to main branch
         │
         ▼
GitHub Actions (cd.yml) triggered
         │
         ▼
    ┌────────────────────────┐
    │   Two Parallel Jobs    │
    └────────────────────────┘
         │           │
         ▼           ▼
   Backend Job   Frontend Job
         │           │
         ▼           ▼
   Build Image   Build Image
    (amd64)       (amd64)
         │           │
         ▼           ▼
   Push to AWS   Push to AWS
    Lightsail     Lightsail
         │           │
         ▼           ▼
   Deploy with   Deploy with
  Health Checks  Health Checks
         │           │
         ▼           ▼
      Live          Live
```

---

## Automated Deployment

### Trigger

Deployments are automatically triggered when code is pushed to the `main` branch.

### Workflow Location

- **Primary workflow**: `.github/workflows/cd.yml`
- **Backend action**: `.github/actions/deploy-backend-to-lightsail/action.yaml`
- **Frontend action**: `.github/actions/deploy-frontend-to-lightsail/action.yaml`

### Process

1. GitHub Actions runner checks out the repository.
2. **GitHub Actions runner authenticates with Infisical using an OIDC machine ID to securely retrieve all deployment secrets.**
3. AWS CLI is configured with the AWS credentials retrieved from Infisical.
4. Old container images are cleaned up from Lightsail.
5. Docker images are built for `linux/amd64` platform.
6. Images are pushed to AWS Lightsail container registry.
7. New deployment is created with updated environment variables injected from Infisical.
8. Health checks validate the deployment (10s interval, 2 healthy/unhealthy thresholds).

### Monitoring Deployment Status

```bash
# Check backend deployment status
aws lightsail get-container-services --service-name jaja-backend \
  --query "containerServices[0].state"

# Check frontend deployment status
aws lightsail get-container-services --service-name jaja-frontend \
  --query "containerServices[0].state"

# View deployment logs
aws lightsail get-container-log --service-name jaja-backend \
  --container-name backend
```

### Expected Deployment States

| State | Description |
|-------|-------------|
| `DEPLOYING` | New deployment in progress |
| `RUNNING` | Deployment successful, service healthy |
| `READY` | Service ready to receive traffic |
| `DISABLED` | Service manually disabled |

---

## Manual Deployment

Use manual deployment only when automated deployment is unavailable or for emergency hotfixes.

### Prerequisites

1. AWS CLI v2 installed and configured
2. Docker installed (for building images)
3. Lightsail plugin installed:
   ```bash
   brew install aws/tap/lightsailctl
   ```
4. Required environment variables injected into your local shell (fetched via Infisical CLI).

### Backend Manual Deployment

```bash
# 1. Navigate to repository root
cd /path/to/jobseeker-analytics

# 2. Build Docker image
docker build -t jaja-backend-backend:manual \
  --platform=linux/amd64 \
  ./backend

# 3. Push to Lightsail
aws lightsail push-container-image \
  --service-name jaja-backend \
  --label backend \
  --image jaja-backend-backend:manual

# 4. Get the image reference from the push output, then deploy
# Replace :jaja-backend.backend.X with the actual version number from step 3
aws lightsail create-container-service-deployment \
  --service-name jaja-backend \
  --containers '{
    "backend": {
      "image": ":jaja-backend.backend.X",
      "environment": {
        "DATABASE_URL": "'"${DATABASE_URL}"'",
        "COOKIE_SECRET": "'"${COOKIE_SECRET}"'",
        "GOOGLE_API_KEY": "'"${GOOGLE_API_KEY}"'",
        "GOOGLE_CLIENT_ID": "'"${GOOGLE_CLIENT_ID}"'",
        "GOOGLE_CLIENT_SECRET": "'"${GOOGLE_CLIENT_SECRET}"'",
        "GOOGLE_CLIENT_REDIRECT_URI": "'"${GOOGLE_CLIENT_REDIRECT_URI}"'",
        "STRIPE_SECRET_KEY": "'"${STRIPE_SECRET_KEY}"'",
        "STRIPE_WEBHOOK_SECRET": "'"${STRIPE_WEBHOOK_SECRET}"'",
        "AWS_KMS_SECRET_ACCESS_KEY": "'"${AWS_KMS_SECRET_ACCESS_KEY}"'",
        "AWS_KMS_ACCESS_KEY_ID": "'"${AWS_KMS_ACCESS_KEY_ID}"'",
        "AWS_KMS_KEY_ARN": "'"${AWS_KMS_KEY_ARN}"'",
        "APP_URL": "'"${APP_URL}"'",
        "API_URL": "'"${API_URL}"'",
        "ORIGIN": "'"${ORIGIN}"'",
        "ENV": "prod"
      },
      "ports": {"8000": "HTTP"}
    }
  }' \
  --public-endpoint '{
    "containerName": "backend",
    "containerPort": 8000,
    "healthCheck": {
      "path": "/",
      "intervalSeconds": 10,
      "healthyThreshold": 2,
      "unhealthyThreshold": 2,
      "timeoutSeconds": 5,
      "successCodes": "200-499"
    }
  }'
```

### Frontend Manual Deployment

```bash
# 1. Navigate to repository root
cd /path/to/jobseeker-analytics

# 2. Build Docker image with build-time args
docker build \
  --build-arg NEXT_PUBLIC_API_URL="${API_URL}" \
  --build-arg NEXT_PUBLIC_APP_URL="${APP_URL}" \
  -t jaja-frontend-frontend:manual \
  --platform=linux/amd64 \
  ./frontend

# 3. Push to Lightsail
aws lightsail push-container-image \
  --service-name jaja-frontend \
  --label frontend \
  --image jaja-frontend-frontend:manual

# 4. Deploy
aws lightsail create-container-service-deployment \
  --service-name jaja-frontend \
  --containers '{
    "frontend": {
      "image": ":jaja-frontend.frontend.X",
      "environment": {
        "NODE_ENV": "production",
        "NEXT_PUBLIC_APP_URL": "'"${APP_URL}"'",
        "NEXT_PUBLIC_API_URL": "'"${API_URL}"'",
        "APP_URL": "'"${APP_URL}"'",
        "GH_APP_ID": "'"${GH_APP_ID}"'",
        "GH_PRIVATE_KEY": "'"${GH_PRIVATE_KEY}"'",
        "GH_INSTALLATION_ID": "'"${GH_INSTALLATION_ID}"'"
      },
      "ports": {"3000": "HTTP"}
    }
  }' \
  --public-endpoint '{
    "containerName": "frontend",
    "containerPort": 3000,
    "healthCheck": {
      "path": "/",
      "intervalSeconds": 10,
      "healthyThreshold": 2,
      "unhealthyThreshold": 2,
      "timeoutSeconds": 5,
      "successCodes": "200-499"
    }
  }'
```

---

## Pre-Deployment Checklist

Complete this checklist before any production deployment:

### Code Quality

- [ ] All tests pass locally (`pytest` for backend, `npm test` for frontend)
- [ ] Linting passes (`ruff check` for backend, `npm run lint` for frontend)
- [ ] No TypeScript errors (`npm run build` completes successfully)
- [ ] PR has been reviewed and approved
- [ ] No security vulnerabilities in dependencies (check Dependabot/Snyk alerts)

### Database

- [ ] Database migrations are included if schema changes are needed
- [ ] Migrations have been tested locally
- [ ] Migrations are backward-compatible (can roll back if needed)
- [ ] No destructive migrations (DROP TABLE, DROP COLUMN) without explicit approval

### Configuration

- [ ] All required environment variables are correctly configured in Infisical
- [ ] No hardcoded secrets in code
- [ ] API endpoint URLs are correct for production

### Communication

- [ ] Team is aware of the deployment
- [ ] Users have been notified if downtime is expected
- [ ] Rollback plan is ready

---

## Post-Deployment Validation

After each deployment, verify the following:

### Automated Health Checks

The deployment includes automated health checks:
- **Interval**: 10 seconds
- **Healthy threshold**: 2 consecutive successful checks
- **Unhealthy threshold**: 2 consecutive failed checks
- **Timeout**: 5 seconds per check
- **Success codes**: 200-499

### Manual Validation Steps

1. **Verify services are running**:
   ```bash
   # Check service status
   aws lightsail get-container-services --service-name jaja-backend
   aws lightsail get-container-services --service-name jaja-frontend
   ```

2. **Test authentication flow**:
   - Navigate to the application URL
   - Click "Login with Google"
   - Complete OAuth flow
   - Verify dashboard loads correctly

3. **Test critical functionality**:
   - [ ] User can view dashboard
   - [ ] Email sync initiates correctly (for premium users)
   - [ ] Payment flow works (test mode)
   - [ ] Coach features work (if applicable)

4. **Check for errors in logs**:
   ```bash
   aws lightsail get-container-log \
     --service-name jaja-backend \
     --container-name backend
   ```

5. **Verify database connectivity**:
   - Check that the application can connect to the database
   - Verify migrations ran successfully (if applicable)


6. **Verify security configuration integrity**
   - Verify that the application's security posture (defined by `get_security_fingerprint`) has not drifted unintentionally during deployment. The expected hash should be stored securely in Infisical as the `EXPECTED_SECURITY_FINGERPRINT` secret.
     1. **Match:** `Current_Hash == EXPECTED_SECURITY_FINGERPRINT`. (Pass: Configuration is unchanged).
     2. **Intentional Mismatch:** `Current_Hash != EXPECTED_SECURITY_FINGERPRINT` AND the associated commit message or PR explicitly authorizes a configuration change (e.g., "Rotate Stripe Webhook Secret").
     3. **Unknown Mismatch:** `Current_Hash != EXPECTED_SECURITY_FINGERPRINT` with no documented authorization.

   - *Execute these steps for a Mismatch.*
     * **If the change was accidental:** Revert the environment variable in Infisical and re-run the job.
     * **If the change was intentional:** Update `EXPECTED_SECURITY_FINGERPRINT` secret in Infisical to match the new current hash and document the rotation in the deployment changelog.


---

## Rollback Procedures

### When to Rollback

Initiate rollback if:
- Health checks fail after deployment
- Critical functionality is broken
- Significant increase in error rates
- Security vulnerability discovered in new code

### Rollback Methods

#### Method 1: Redeploy Previous Git Commit (Recommended)

```bash
# 1. Identify the bad commit
git log --oneline -10

# 2. Revert the commit on the main branch
git checkout main
git revert <bad-commit-sha>

# 3. Push to trigger the rollback deployment
git push origin main

#### Method 2: Redeploy Previous Container Image

```bash
# 1. List available images
aws lightsail get-container-images --service-name jaja-backend

# 2. Identify the previous working image (e.g., :jaja-backend.backend.5)

# 3. Redeploy with the previous image
aws lightsail create-container-service-deployment \
  --service-name jaja-backend \
  --containers '{
    "backend": {
      "image": ":jaja-backend.backend.5",
      ... (same environment variables as current deployment)
    }
  }' \
  --public-endpoint '{ ... }'
```

#### Method 3: Database Migration Rollback

If the issue is related to database migrations:

```bash
# 1. Connect to a machine with database access

# 2. Check current migration version
alembic current

# 3. Downgrade to previous version
alembic downgrade -1

# 4. Or downgrade to specific version
alembic downgrade <revision_id>
```

**Warning**: Only rollback migrations if you're certain the rollback is safe and won't cause data loss.

### Rollback Verification

After rollback:
1. Verify services are healthy
2. Test critical user flows
3. Check error rates return to normal
4. Document the incident

---

## Backup and Restore

### Database Backups

#### AWS Lightsail Automated Backups

AWS Lightsail managed databases include automated backups:

| Setting | Value |
|---------|-------|
| Backup retention | 7 days (default) |
| Backup window | Automatic (AWS-managed) |
| Point-in-time recovery | Supported |

#### Create Manual Backup (Snapshot)

```bash
# Create a snapshot before major changes
aws lightsail create-relational-database-snapshot \
  --relational-database-name <your-database-name> \
  --relational-database-snapshot-name "pre-deployment-$(date +%Y%m%d-%H%M%S)"

# List available snapshots
aws lightsail get-relational-database-snapshots
```

#### Export Database (pg_dump)

For complete database exports:

```bash
# 1. Get database connection info
aws lightsail get-relational-database \
  --relational-database-name <your-database-name>

# 2. Get master password
aws lightsail get-relational-database-master-user-password \
  --relational-database-name <your-database-name>

# 3. Export database
PGPASSWORD="<master-password>" pg_dump \
  -h <endpoint-address> \
  -p <port> \
  -U <master-username> \
  -d <database-name> \
  -F c \
  -f backup-$(date +%Y%m%d-%H%M%S).dump
```

### Restore Procedures

#### Restore from Lightsail Backup (Point-in-Time Recovery)

AWS Lightsail managed databases use Point-in-Time Recovery (PITR) for automated backups. This allows you to restore the database to any specific minute within the last 7 days.

**Prerequisite:** Retrieve your deployment configuration from Infisical:
* **Region:** Use the `AWS_REGION_NAME` secret.
* **Target Database:** Use the `AWS_DATABASE_NAME` secret.

```bash
# 1. Check the latest restorable time for your database
aws lightsail get-relational-database \
  --region <AWS_REGION_NAME> \
  --relational-database-name <AWS_DATABASE_NAME> \
  --query "relationalDatabase.latestRestorableTime"

# 2. Option A: Create a new database restored to the latest possible minute
aws lightsail create-relational-database-from-snapshot \
  --region <AWS_REGION_NAME> \
  --relational-database-name <new-database-name> \
  --source-relational-database-name <AWS_DATABASE_NAME> \
  --use-latest-restorable-time \
  --availability-zone <az> \
  --publicly-accessible

# 2. Option B: Create a new database restored to a specific past timestamp (Unix epoch time)
aws lightsail create-relational-database-from-snapshot \
  --region <AWS_REGION_NAME> \
  --relational-database-name <new-database-name> \
  --source-relational-database-name <AWS_DATABASE_NAME> \
  --restore-time <unix-timestamp> \
  --availability-zone <az> \
  --publicly-accessible

# 3. Update application to use the new database
# Update DATABASE_URL in Infisical and redeploy

### Application State Backup

The application is stateless beyond the database. To fully restore:

1. **Code**: Available in Git repository
2. **Configuration**: Stored in Infisical
3. **Database**: Restore from snapshot or pg_dump
4. **Container Images**: Rebuilt from source code

---

## Disaster Recovery

### Recovery Time Objectives

| Scenario | RTO Target | RPO Target |
|----------|------------|------------|
| Container failure | < 5 minutes | 0 (stateless) |
| Database failure | < 30 minutes | < 1 hour |
| Region failure | < 4 hours | < 1 hour |
| Complete rebuild | < 8 hours | Last backup |

### Disaster Scenarios and Recovery

#### Scenario 1: Container Service Failure

**Symptoms**: Service unreachable, health checks failing

**Recovery**:
```bash
# 1. Check service status
aws lightsail get-container-services --service-name jaja-backend

# 2. If DISABLED, re-enable
aws lightsail update-container-service \
  --service-name jaja-backend \
  --power nano \
  --scale 1 \
  --is-disabled false

# 3. If still failing, redeploy
# Trigger by pushing to main or manual deployment
```

#### Scenario 2: Database Corruption or Failure

**Symptoms**: Application errors, database connection failures, accidental data deletion.

**Recovery**:
*(Note: Ensure you have retrieved `AWS_REGION_NAME` and `AWS_DATABASE_NAME` from Infisical before starting.)*

```bash
# 1. Check database status and get latest restorable time
aws lightsail get-relational-database \
  --region <AWS_REGION_NAME> \
  --relational-database-name <AWS_DATABASE_NAME>

# 2. Restore database to a new instance using Point-in-Time Recovery (PITR)
aws lightsail create-relational-database-from-snapshot \
  --region <AWS_REGION_NAME> \
  --relational-database-name <new-database-name> \
  --source-relational-database-name <AWS_DATABASE_NAME> \
  --use-latest-restorable-time \
  --availability-zone <az> \
  --publicly-accessible

# 3. Securely retrieve the master password for the newly restored database
aws lightsail get-relational-database-master-user-password \
  --region <AWS_REGION_NAME> \
  --relational-database-name <new-database-name>

# 4. Update DATABASE_URL in GitHub Secrets with the new endpoint and credentials

# 5. Redeploy application to pick up the new database connection

#### Scenario 3: Complete Infrastructure Loss

**Recovery Steps**:

1. **Recreate Lightsail Container Services**:
   ```bash
   aws lightsail create-container-service \
     --service-name jaja-backend \
     --power nano \
     --scale 1

   aws lightsail create-container-service \
     --service-name jaja-frontend \
     --power nano \
     --scale 1
   ```

2. **Restore Database**: Follow [Restore Procedures](#restore-procedures)

3. **Configure Secrets**: Ensure all secrets are correctly configured in Infisical

4. **Deploy Application**: Push to main branch or manual deploy

5. **Verify**: Complete [Post-Deployment Validation](#post-deployment-validation)

### Regular DR Testing

Recommended quarterly:
- [ ] Test database restore from snapshot
- [ ] Verify backup integrity (restore to test environment)
- [ ] Practice rollback procedures
- [ ] Review and update this runbook

---

## Secrets Management

### Infisical (Production)

All production secrets are securely managed and stored in Infisical under the prod environment. The GitHub Actions CI/CD pipeline authenticates with Infisical automatically using an OIDC machine ID to retrieve these secrets at runtime, ensuring no credentials are unnecessarily stored or exposed directly within GitHub.

| Secret | Purpose | Rotation Frequency |
|--------|---------|-------------------|
| `APP_URL` | Routing | N/A (config) |
| `API_URL` | Routing | N/A (config) |
| `NEXT_PUBLIC_APP_URL` | Routing | N/A (config) |
| `NEXT_PUBLIC_API_URL` | Routing | N/A (config) |
| `AWS_DATABASE_REGION` | AWS region | N/A (config) |
| `AWS_DATABASE_NAME` | AWS region | N/A (config) |
| `AWS_KMS_ACCESS_KEY_ID` | AWS KMS | N/A (config) |
| `AWS_KMS_SECRET_ACCESS_KEY` | AWS KMS | N/A (config) |
| `AWS_KMS_KEY_ARN` | AWS KMS | N/A (config) |
| `DATABASE_URL` | Storage | N/A (only if new database is created or restored from backup) |
| `COOKIE_SECRET` | Session signing | Annual |
| `GOOGLE_CLIENT_ID` | OAuth client | As needed |
| `GOOGLE_CLIENT_SECRET` | OAuth client | As needed |
| `GOOGLE_CLIENT_REDIRECT_URI` | OAuth client | As needed |
| `GOOGLE_API_KEY` | Gemini API | As needed |
| `STRIPE_SECRET_KEY` | Payment processing | As needed |
| `STRIPE_WEBHOOK_SECRET` | Webhook verification | As needed |
| `GH_APP_ID` | GitHub App | N/A |
| `GH_PRIVATE_KEY` | GitHub App | Annual |
| `GH_INSTALLATION_ID` | GitHub App | N/A |
| `NODE_ENV` | Settings Configuration | N/A |
| `ENV` | Settings Configuration | N/A |
| `IPINFO_TOKEN` | Settings Configuration | N/A |

### Secret Rotation Procedure

1. Generate new secret value
2. Update the secret in the Infisical Dashboard (under the prod environment).
3. Trigger a new deployment in GitHub Actions to apply the updated environment variables.
4. Verify application functionality
5. Revoke old secret (if applicable)

### Local Development

Local secrets are typically pulled down via the Infisical CLI or stored in:
- `backend/.env` (gitignored)
- `frontend/.env` (gitignored)

See `backend/.env.example` and `frontend/.env.sample` for required variables.

---

## Troubleshooting

### Deployment Warnings

#### **Warning: Security Configuration Mismatch**
* **Symptoms**: A yellow warning banner appears in the GitHub Action summary stating "Security Configuration Mismatch".
* **Cause**: The current environment variables in the runner do not match the expected cryptographic fingerprint.
* **Impact**: The deployment will continue (Fail-Safe), but the configuration integrity cannot be guaranteed.
* **Resolution**: 
    1. Check if a secret was recently rotated without updating the fingerprint.
    2. Audit Infisical for any unauthorized changes.
    3. Update the `EXPECTED_SECURITY_FINGERPRINT` secret once the configuration is verified.

### Common Issues

#### Deployment Stuck in DEPLOYING State

```bash
# Check deployment status and logs
aws lightsail get-container-services --service-name jaja-backend

aws lightsail get-container-log \
  --service-name jaja-backend \
  --container-name backend
```

**Common causes**:
- Docker image build failure
- Health check failures
- Invalid environment variables

#### Health Checks Failing

```bash
# Test health endpoint directly
curl -v https://<service-url>/
```

**Common causes**:
- Application crash on startup
- Database connection issues
- Missing environment variables

#### Database Connection Errors

```bash
# Verify database is accessible
aws lightsail get-relational-database \
  --relational-database-name <database-name>

# Check if database is in AVAILABLE state
```

**Common causes**:
- Database password changed
- Network/security group issues
- Database at capacity

#### Container Image Push Failures

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check Lightsail service exists
aws lightsail get-container-services
```

### Log Access

```bash
# Backend logs
aws lightsail get-container-log \
  --service-name jaja-backend \
  --container-name backend

# Frontend logs
aws lightsail get-container-log \
  --service-name jaja-frontend \
  --container-name frontend

# Filter by time (last hour)
aws lightsail get-container-log \
  --service-name jaja-backend \
  --container-name backend \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) # On macOS, use: date -u -v-1H +'%Y-%m-%dT%H:%M:%SZ'
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-08 | Deployment Team | Initial runbook creation |
| 1.1 | 2026-02-21 | Deployment Team | Migrated secrets management from GitHub Secrets to Infisical OIDC integration |
