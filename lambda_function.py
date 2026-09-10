import boto3
import requests
import json
import base64
import os
import re
from datetime import datetime, timezone

sqs = boto3.client("sqs")


def lambda_handler(event, context):
    """Validates and forwards contact form submissions to SQS after reCAPTCHA verification."""

    request_method = event.get('requestContext', {}).get('http', {}).get('method', 'POST')
    request_origin = event.get('headers', {}).get('origin') or event.get('headers', {}).get('Origin') or ''
    allowed_origins = {'https://alma-artifex.com', 'https://www.alma-artifex.com'}
    recaptcha_secret = os.environ.get('RECAPTCHA_SECRET')
    queue_url = os.environ.get('QUEUE_URL')

    # CORS preflight
    if request_method == 'OPTIONS':
        return {
            'statusCode': 204 if request_origin in allowed_origins else 403,
            'headers': {
                'Access-Control-Allow-Origin': request_origin if request_origin in allowed_origins else 'https://alma-artifex.com',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Content-Length': '0'
            },
            'body': '',
        }

    cors_headers = {
        'Access-Control-Allow-Origin': request_origin if request_origin in allowed_origins else 'https://alma-artifex.com',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    }

    def respond(status_code, body):
        return {
            'statusCode': status_code,
            'headers': cors_headers,
            'body': json.dumps(body)
        }

    try:
        if not recaptcha_secret:
            print('Missing RECAPTCHA_SECRET')
            return respond(500, {'error': 'Server configuration error'})

        if not queue_url:
            print('Missing QUEUE_URL')
            return respond(500, {'error': 'Server configuration error'})

        # Decode body if API Gateway base64-encoded it, otherwise use as-is
        raw_body = base64.b64decode(event.get('body') or '').decode('utf-8') if event.get('isBase64Encoded') else event.get('body') or '{}'
        body = json.loads(raw_body)

        name = body.get('name')
        email = body.get('email')
        message = body.get('message')
        captcha_token = body.get('captchaToken')
        reference = body.get('reference')
        source = body.get('source')

        # Honeypot: silently accept without processing
        if str(reference or '').strip():
            return respond(200, {'ok': True})

        if not all([name, email, message, captcha_token]):
            return respond(400, {'error': 'Missing req fields'})

        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return respond(400, {'error': 'Invalid email'})

        verify_response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': recaptcha_secret, 'response': captcha_token}
        )

        if not verify_response.ok:
            print('reCAPTCHA verification HTTP failure', verify_response.status_code)
            return respond(502, {'error': 'Captcha verification unavailable'})

        verify_data = verify_response.json()

        if not verify_data.get('success'):
            print('reCAPTCHA rejected token', verify_data.get('error-codes'))
            return respond(400, {'error': 'reCAPTCHA verification failed'})

        sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps({
            'name': name,
            'email': email,
            'message': message,
            'source': source or 'unknown',
            'submittedAt': datetime.now(timezone.utc).isoformat()
        }))

        return respond(200, {'ok': True})

    except Exception as error:
        print('Exception:', error)
        return respond(500, {'error': 'Server error'})

    finally:
        print('complete')