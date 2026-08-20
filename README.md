# SecDashboard 🛡️

A lightweight, ultra-fast DevSecOps portal and DefectDojo alternative built for Kubernetes and Terraform infrastructure.

- **Zero heavy dependencies**: Requires only PostgreSQL (no Redis, no Celery workers, no Nginx).
- **Multi-Tool Ingestion**: Native parsers for **Checkov** (IaC), **Trivy** (IaC & CVEs), and **TruffleHog** (Verified Secrets).
- **Modern UI**: Interactive severity breakdown, charts, instant search, and code-level remediation guidelines.
- **Single Container**: Packaged into a lightweight Docker image on port `8080`.

---

## 🚀 Quick Start with Docker

```bash
docker run -d -p 8080:8080 \
  -e DATABASE_URL="postgresql://user:password@host:5432/dbname" \
  --name sec-dashboard \
  sec-dashboard:latest
```

Open `http://localhost:8080` in your browser.

---

## 📡 Uploading Scans from GitHub Actions CI

Upload results directly from your existing CI workflows:

```yaml
# 1. Upload Checkov JSON
- name: Upload Checkov to SecDashboard
  if: always()
  run: |
    curl -X POST "https://your-dashboard-url.com/api/upload" \
      -F "tool=checkov" \
      -F "repository=tf-network-module" \
      -F "branch=${{ github.ref_name }}" \
      -F "commit_sha=${{ github.sha }}" \
      -F "file=@reports/checkov-report.json"

# 2. Upload Trivy JSON
- name: Upload Trivy to SecDashboard
  if: always()
  run: |
    curl -X POST "https://your-dashboard-url.com/api/upload" \
      -F "tool=trivy" \
      -F "repository=tf-essential-module" \
      -F "branch=${{ github.ref_name }}" \
      -F "commit_sha=${{ github.sha }}" \
      -F "file=@reports/trivy-report.json"

# 3. Upload TruffleHog JSON
- name: Upload TruffleHog to SecDashboard
  if: always()
  run: |
    curl -X POST "https://your-dashboard-url.com/api/upload" \
      -F "tool=trufflehog" \
      -F "repository=infra" \
      -F "branch=${{ github.ref_name }}" \
      -F "commit_sha=${{ github.sha }}" \
      -F "file=@reports/trufflehog-report.json"
```
