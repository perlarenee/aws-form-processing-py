#import boto3 and sqs const
import boto3
sqs = boto3.client("sqs")

#import json and base64 and os
import requests
import json
import base64
import os
import re
from datetime import datetime, timezone

#serialize data into json 
## json.dumps(py_dict_data)
#convert text to bytes, then endoe to base 64 types
## b64_bytes = base54.b64encode(json_string.encode('utf-8))
#turn base64 back into readable text string
## b64string = b64_bytes.decode('utf-8')

#handler wraper, does boto3 need this?

def handler(event, context):
    """Validates and forwards contact form submissions to SQS after reCAPTCHA verification."""
    
    #get method out of event dict by chaining get
    request_method = event.get('requestContext',{}).get('http',{}).get('method','POST')
    #look for origin but check if uppercase
    request_origin = event.get('headers',{}).get('origin') or event.get('headers',{}).get('Origin') or ''
    allowed_origins = {'https://alma-artifex.com', 'https://www.alma-artifex.com'}
    recaptcha_secret = os.environ.get('RECAPTCHA_SECRET')
    queue_url = os.environ.get('QUEUE_URL')

    #handles first request from origin, check if allowed origin, return headers and 204 if ready else 403
    if request_method == 'OPTIONS':
        return {
            'statusCode':  204 if request_origin in allowed_origins else 403,
            'headers': {
                'Access-Control-Allow-Origin':request_origin if request_origin in allowed_origins else 'https://alma-artifex.com',
                'Access-Control-Allow-Methods':'POST, OPTIONS',
                'Access-Control-Allow-Headers':'Content-Type',
                'Content-Length':'0'
            },
            'body': '',
        }

    #helper: Cors headers
    cors_headers =  {
        'Access-Control-Allow-Origin':request_origin if request_origin in allowed_origins else 'https://alma-artifex.com',
        'Access-Control-Allow-Methods':'POST, OPTIONS',
        'Access-Control-Allow-Headers':'Content-Type',
        'Content-Type':'application/json'
    }

    #helper: respond function
    def respond(status_code,body):
        return {
            'statusCode': status_code,
            'headers': cors_headers,
            'body':json.dumps(body)
        }

    try:
        #if recaptcha secret is missing from env var, fail with 500 status code
        if not recaptcha_secret:
            print('Missing Recaptcha Secret')
            return respond(500,{'error': 'Server configuration error'})
        #if queue url missing from env var, fail with 500 status code
        if not queue_url:
            print('Missing Queue url')
            return respond(500,{'error':'Server configuration error'})

        #get raw body, if in base64, decode to uft8, otherwise just get the body, fallbacks
        raw_body = base64.b64decode(event.get('body') or '').decode('utf-8') if event.get('isBase64Encoded') else event.get('body') or '{}'
        #parse json to raw body
        body = json.loads(raw_body)
        #pull data from body
        name = body.get('name')
        email = body.get('email')
        message = body.get('message')
        captcha_token = body.get('captchaToken')
        reference = body.get('reference')
        source = body.get('source')

        #reference/test
        if str(reference or '').strip():
            return respond(200,{'ok':True})

        #values
        if not all([name, email, message, captcha_token]):
            return respond(400,{'error':'Missing req fields'})

        #match email with regex pattern
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern,email):
            return respond(400,{'error':'Invalid email'})

        #request response from google recaptcha
        verify_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret':recaptcha_secret,'response':captcha_token})

        #if verify response not ok, return fail
        if not verify_response.ok:
            print('reCAPTCHA verification HTTP failure',verify_response.status_code)
            return respond(502,{'error':'Captcha verification unavailable'})

        #verify recaptcha
        verify_data = verify_response.json()

        if not verify_data.get('success'):
            print('reCAPTCHA rejected token',verify_data.get('error-codes'))
            return respond(400,{'error':'reCAPTCHA verification failed'})

        sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps({
            'name':name,
            'email': email,
            'message': message,
            'source': source or 'unknown',
            'submittedAt': datetime.now(timezone.utc).isoformat()
            }))

        return respond(200,{'ok':True})

    except Exception as error:
        print('Exception:',error)
        return respond(500,{'error':'Server error'})

    finally:
        print('complete')