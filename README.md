# aws-form-processing-py
 
Python (AWS Lambda) contact form backend
 
## What it does
 
Sits behind API Gateway and:
 
1. Handles CORS preflight requests.
2. Validates a form submission (name, email, message, reCAPTCHA token).
3. Silently drops submissions that fill in a hidden honeypot field.
4. Rejects missing fields or an invalid email format.
5. Verifies the reCAPTCHA token with Google.
6. Sends valid submissions to an SQS queue for downstream processing.
Errors returned to the caller are generic. Full exception detail goes to CloudWatch Logs only.
 
## Stack
 
- Python 3.14
- boto3 (AWS SDK)
- requests (HTTP calls to reCAPTCHA)
## Environment variables
 
| Variable | Purpose |
|---|---|
| QUEUE_URL | SQS queue URL |
| RECAPTCHA_SECRET | reCAPTCHA v2 secret key |
 
## Local setup
 
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
 
## Status
 
Functional first version. Next: tests, logging module, type hints.
 