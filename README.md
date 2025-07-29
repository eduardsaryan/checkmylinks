# Check My links

## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy? [Use the template at the bottom](#editing-this-readme)!

## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/topics/git/add_files/#add-files-to-a-git-repository) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://code.checkmylinks.io/main/checkmylinks.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://code.checkmylinks.io/main/checkmylinks/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/user/project/merge_requests/auto_merge/)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

=======
# CheckMyLinks - Dead Link Checker SaaS

A professional SaaS tool for finding broken links on websites, built with Node.js, Express, PostgreSQL, and Redis.

## Features

- 🔍 Comprehensive link scanning
- 📊 Detailed reporting with statistics
- 🚀 Asynchronous processing with queues
- 💳 Stripe integration for payments
- 📧 Email notifications
- 🔐 JWT authentication
- 📈 Rate limiting
- 🐳 Docker ready

## Quick Start

### Prerequisites

- Node.js 16+
- PostgreSQL 13+
- Redis 6+
- Stripe account (for payments)
- SendGrid account (for emails)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/checkmylinks.git
cd checkmylinks
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up the database**
```bash
# Create database
createdb checkmylinks

# Run the application (tables will be created automatically)
npm start
```

5. **Start Redis**
```bash
redis-server
```

6. **Run the application**
```bash
# Development
npm run dev

# Production
npm start
```

## Deployment

### Using Docker

1. **Build and run with Docker Compose**
```bash
docker-compose up -d
```

### Manual Deployment on VPS

1. **Set up Ubuntu VPS**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Redis
sudo apt install -y redis-server

# Install Nginx
sudo apt install -y nginx

# Install PM2
sudo npm install -g pm2
```

2. **Configure PostgreSQL**
```bash
sudo -u postgres psql
CREATE DATABASE checkmylinks;
CREATE USER checkmylinks WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE checkmylinks TO checkmylinks;
\q
```

3. **Configure Nginx**
```nginx
server {
    listen 80;
    server_name checkmylinks.io;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

4. **Set up SSL with Let's Encrypt**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d checkmylinks.io
```

5. **Start with PM2**
```bash
pm2 start server.js --name checkmylinks
pm2 save
pm2 startup
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Scans
- `POST /api/scans` - Create new scan (authenticated)
- `GET /api/scans` - Get user's scans (authenticated)
- `GET /api/scans/:id` - Get scan details (authenticated)
- `POST /api/public/scan` - Public scan (limited to 50 links)

### Export
- `GET /api/scans/:id/export/csv` - Export scan as CSV (authenticated)

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | checkmylinks |
| DB_USER | Database user | postgres |
| DB_PASSWORD | Database password | - |
| REDIS_HOST | Redis host | localhost |
| REDIS_PORT | Redis port | 6379 |
| JWT_SECRET | JWT secret key | - |
| PORT | Server port | 3000 |

## Monitoring

### Health Check
```bash
curl http://localhost:3000/api/health
```

### Logs
```bash
# PM2 logs
pm2 logs checkmylinks

# Docker logs
docker-compose logs -f app
```

## Scaling

### Horizontal Scaling
1. Add more worker processes for the queue
2. Use Redis Cluster for queue distribution
3. Load balance with Nginx

### Database Optimization
```sql
-- Add indexes for performance
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scans_created_at ON scans(created_at);
```

## Security

- Helmet.js for security headers
- Rate limiting on all endpoints
- SQL injection protection with parameterized queries
- Password hashing with bcrypt
- JWT tokens with expiration
- HTTPS enforcement

## Maintenance

### Database Backup
```bash
# Backup
pg_dump checkmylinks > backup.sql

# Restore
psql checkmylinks < backup.sql
```

### Updates
```bash
# Update dependencies
npm update

# Check for vulnerabilities
npm audit
```

## License

MIT License - feel free to use this for your business!

## Support

For issues or questions, create an issue in the GitHub repository.
>>>>>>> 765fa1e (Initial commit)
