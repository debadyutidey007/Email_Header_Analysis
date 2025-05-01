import os
import re
import json
import email
import socket
import base64
import hashlib
import logging
import tldextract
import traceback
import requests
import validators
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from email.header import decode_header
from typing import Dict, List, Set, Tuple, Union, Optional, Any
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Import OpenAI for AI-powered analysis
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Set up OpenAI client
openai_api_key = os.environ.get("OPENAI_API_KEY")
openai_client = OpenAI(api_key=openai_api_key)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure upload settings
UPLOAD_FOLDER = '/tmp/uploads'
ALLOWED_EXTENSIONS = {'eml'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Limit uploads to 10MB

# Header importance level for analysis
HEADER_IMPORTANCE = {
    'from': 'critical',
    'return-path': 'critical',
    'received': 'high',
    'message-id': 'high',
    'x-originating-ip': 'high',
    'authentication-results': 'high',
    'dkim-signature': 'high',
    'spf': 'high',
    'x-spam-status': 'medium',
    'x-mailer': 'medium',
    'user-agent': 'medium',
    'content-type': 'medium',
    'mime-version': 'low',
    'date': 'low',
    'subject': 'low',
    'to': 'low',
    'cc': 'low',
    'reply-to': 'medium',
    'arc-authentication-results': 'high',
    'arc-message-signature': 'high',
    'arc-seal': 'high',
    'x-ms-exchange-antispam-messagedata': 'medium',
    'x-forefront-antispam-report': 'medium',
    'x-ms-oob-tlc-oobclassifiers': 'medium',
    'x-microsoft-antispam': 'medium',
    'x-ms-traffictypediagnostic': 'low',
    'x-exchange-antispam-report-cfa-test': 'medium',
    'x-sender': 'medium',
    'x-sender-ip': 'high',
    'sender': 'high',
    'delivered-to': 'medium',
    'x-google-smtp-source': 'medium',
    'x-received': 'medium',
    'x-gm-message-state': 'medium',
}


def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def decode_value(value):
    """Decode header value that might be encoded"""
    if not value:
        return ""
    
    decoded_parts = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            try:
                if encoding:
                    decoded_parts.append(part.decode(encoding, errors='replace'))
                else:
                    decoded_parts.append(part.decode('utf-8', errors='replace'))
            except (UnicodeDecodeError, LookupError):
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:
            decoded_parts.append(part)
    
    return ' '.join(decoded_parts)


def extract_ip_addresses(text):
    """Extract IP addresses from a string using regex"""
    if not text:
        return []
    
    # IPv4 pattern
    ipv4_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    # IPv6 pattern - comprehensive pattern for various IPv6 formats
    ipv6_pattern = r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)'
    
    ipv4_addresses = re.findall(ipv4_pattern, text)
    ipv6_addresses = re.findall(ipv6_pattern, text)
    
    # Validate IP addresses to filter out false positives
    valid_ipv4 = [ip for ip in ipv4_addresses if validators.ipv4(ip)]
    
    return valid_ipv4 + ipv6_addresses


def extract_domains(text):
    """Extract domains from a string using tldextract"""
    if not text:
        return []
    
    # Basic domain pattern for initial extraction
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    
    potential_domains = re.findall(domain_pattern, text)
    validated_domains = []
    
    for domain in potential_domains:
        # Use tldextract to properly analyze domain components
        extract_result = tldextract.extract(domain)
        if extract_result.suffix and extract_result.domain:  # Valid domain must have both
            validated_domains.append(domain)
    
    return validated_domains


def ip_reputation_check(ip):
    """Perform IP reputation check using AbuseIPDB API (if available)"""
    try:
        # Use a dummy response as we don't have an actual API key
        # In a real implementation, you would add your AbuseIPDB API key to environment variables
        return {
            "score": 0,  # Lower is better
            "reports": 0,
            "last_reported": None,
            "country": "Unknown",
            "isp": "Unknown",
            "usageType": "Unknown"
        }
    except Exception as e:
        logging.warning(f"Failed to check IP reputation for {ip}: {str(e)}")
        return None


def domain_reputation_check(domain):
    """Perform domain reputation check"""
    try:
        # Attempt to resolve domain MX records - important for email domain validation
        mx_records = []
        try:
            mx_records = sorted(socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM))
        except socket.gaierror:
            pass
        
        # Check domain age and registration info
        # Note: This would normally use a WHOIS API, but we're keeping it simple
        domain_info = {
            "mx_records": len(mx_records) > 0,
            "registered": True,  # Placeholder
            "creation_date": None,  # Placeholder
            "registrar": "Unknown",  # Placeholder
            "score": 0  # Lower is better
        }
        
        return domain_info
    except Exception as e:
        logging.warning(f"Failed to check domain reputation for {domain}: {str(e)}")
        return None


def analyze_ai_phishing_patterns(headers, email_content=None):
    """Use OpenAI to analyze email headers for sophisticated phishing patterns"""
    try:
        if not openai_api_key:
            return {
                "ai_analysis": False,
                "message": "OpenAI API key not configured"
            }

        # Prepare the headers for analysis
        headers_text = "\n".join([f"{key}: {value['value']}" for key, value in headers.items()])
        
        # Construct the prompt
        system_prompt = (
            "You are an expert email security analyst specializing in detecting phishing and spoofing attempts. " 
            "Analyze the following email headers and provide insights on potential security threats. " 
            "Focus on identifying spoofing, phishing indicators, and authentication failures. " 
            "Be specific about what makes this email suspicious or legitimate."
        )
        
        user_prompt = f"Email Headers:\n{headers_text}\n\nAnalyze these headers for any signs of phishing, spoofing, or other email-based attacks."
        
        # Call OpenAI API
        response = openai_client.chat.completions.create(
            model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=1000
        )
        
        analysis_text = response.choices[0].message.content
        
        # Extract a summary judgment with a structured prompt
        judgment_prompt = f"Based on the email headers analysis you just performed, provide a structured JSON response with the following fields:\n1. 'risk_score': A number from 0 (no risk) to 10 (highest risk) representing the likelihood this is a malicious email.\n2. 'confidence': A number from 0 to 1 representing your confidence in this assessment.\n3. 'classification': One of ['legitimate', 'suspicious', 'likely_phishing', 'malicious']\n4. 'key_indicators': A list of strings describing the most important indicators that led to your conclusion.\n5. 'recommendations': A list of strings with recommendations for the recipient."

        judgment_response = openai_client.chat.completions.create(
            model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
            messages=[
                {"role": "system", "content": "You are an expert email security analyst. Provide accurate, structured judgments about email security risks."},
                {"role": "user", "content": f"Analysis:\n{analysis_text}\n\n{judgment_prompt}"}
            ],
            response_format={"type": "json_object"},
            max_tokens=1000
        )
        
        structured_judgment = json.loads(judgment_response.choices[0].message.content)
        
        return {
            "ai_analysis": True,
            "detailed_analysis": analysis_text,
            "structured_judgment": structured_judgment
        }
        
    except Exception as e:
        logging.error(f"OpenAI API error: {str(e)}\n{traceback.format_exc()}")
        return {
            "ai_analysis": False,
            "message": f"AI analysis failed: {str(e)}"
        }


def calculate_headers_hash(headers):
    """Calculate a hash of the headers to detect similar phishing campaigns"""
    # Create a stable representation of critical headers
    critical_headers = ['from', 'reply-to', 'return-path', 'message-id']
    header_values = []
    
    for header in critical_headers:
        # Find the header (case-insensitive)
        found_header = next((h for h in headers if h.lower() == header), None)
        if found_header:
            header_values.append(headers[found_header]['value'])
    
    # Create a hash from the joined values
    hash_input = '|'.join(header_values)
    header_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    
    return header_hash


def analyze_headers_chronology(headers):
    """Analyze the timeline of Received headers to detect anomalies"""
    received_headers = [h for h in headers if h.lower() == 'received']
    date_header = next((h for h in headers if h.lower() == 'date'), None)
    
    timeline = []
    anomalies = []
    
    # Process Received headers (most recent first in email headers)
    for i, header in enumerate(received_headers):
        value = headers[header]['value']
        
        # Extract date from Received header
        date_match = re.search(r';\s*(.+?)(?:\s*\(|$)', value)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                # Try to parse the date
                timestamp = parsedate_to_datetime(date_str)
                timeline.append({
                    'header_index': i,
                    'timestamp': timestamp,
                    'value': value
                })
            except Exception as e:
                anomalies.append(f"Could not parse date in Received header {i}: {str(e)}")
    
    # Add the Date header if present
    if date_header:
        try:
            date_value = headers[date_header]['value']
            timestamp = parsedate_to_datetime(date_value)
            timeline.append({
                'header_index': 'date',
                'timestamp': timestamp,
                'value': date_value
            })
        except Exception as e:
            anomalies.append(f"Could not parse Date header: {str(e)}")
    
    # Sort timeline by timestamp
    timeline.sort(key=lambda x: x['timestamp'] if isinstance(x['timestamp'], datetime) else datetime.min)
    
    # Check for chronological anomalies
    if len(timeline) > 1:
        for i in range(len(timeline) - 1):
            curr = timeline[i]
            next_item = timeline[i + 1]
            
            if isinstance(curr['timestamp'], datetime) and isinstance(next_item['timestamp'], datetime):
                time_diff = (next_item['timestamp'] - curr['timestamp']).total_seconds()
                
                # Flag large time gaps or backwards time (more than 30 min threshold)
                if time_diff > 1800:  # 30 minutes in seconds
                    anomalies.append(f"Large time gap ({time_diff/60:.1f} min) between headers")
                elif time_diff < 0:
                    anomalies.append(f"Backwards time flow detected ({abs(time_diff)/60:.1f} min)")
    
    return {
        'timeline': timeline,
        'anomalies': anomalies
    }


def extract_email_metadata(msg):
    """Extract metadata from email such as client info, timezone, languages"""
    metadata = {
        'client_info': None,
        'languages': set(),
        'has_attachments': False,
        'content_types': set(),
        'urls': set()
    }
    
    # Check X-Mailer or User-Agent headers for client info
    x_mailer = next((h for h in msg if h.lower() == 'x-mailer'), None)
    user_agent = next((h for h in msg if h.lower() == 'user-agent'), None)
    
    if x_mailer:
        metadata['client_info'] = decode_value(msg[x_mailer])
    elif user_agent:
        metadata['client_info'] = decode_value(msg[user_agent])
    
    # Check for Content-Language header
    content_language = next((h for h in msg if h.lower() == 'content-language'), None)
    if content_language:
        langs = decode_value(msg[content_language]).split(',')
        metadata['languages'].update([lang.strip() for lang in langs])
    
    # Check Accept-Language header
    accept_language = next((h for h in msg if h.lower() == 'accept-language'), None)
    if accept_language:
        langs = re.findall(r'([a-zA-Z]{2}(?:-[a-zA-Z]{2})?)', decode_value(msg[accept_language]))
        metadata['languages'].update(langs)
    
    # Check for attachments and content types
    for part in msg.walk():
        content_type = part.get_content_type()
        metadata['content_types'].add(content_type)
        
        if part.get_content_disposition() in ['attachment', 'inline']:
            metadata['has_attachments'] = True
    
    # Extract URLs from the text parts
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w/-]*'
    for part in msg.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            try:
                content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                urls = re.findall(url_pattern, content)
                metadata['urls'].update(urls)
            except Exception as e:
                logging.warning(f"Could not extract URLs: {str(e)}")
    
    # Convert sets to lists for JSON serialization
    metadata['languages'] = list(metadata['languages'])
    metadata['content_types'] = list(metadata['content_types'])
    metadata['urls'] = list(metadata['urls'])
    
    return metadata


def analyze_email_file(file_path):
    """Analyze an email file for header information and security signals with advanced analysis"""
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
    except Exception as e:
        logging.error(f"Error opening email file: {str(e)}")
        raise ValueError(f"Could not parse email file: {str(e)}")
    
    # Initialize analysis results
    analysis = {
        'headers': {},
        'summary': {
            'suspicious_indicators': [],
            'domains': set(),
            'ip_addresses': set(),
            'mismatch_domains': False,
            'missing_headers': [],
            'spf_result': 'unknown',
            'dkim_result': 'unknown',
            'dmarc_result': 'unknown',
            'arc_result': 'unknown',
            'threat_level': 'unknown',
        },
        'domain_analysis': {},
        'ip_analysis': {},
        'chronology': {},
        'metadata': {},
        'ai_analysis': {}
    }
    
    # Process header information
    for header, value in msg.items():
        header_key = header.lower()
        if header_key in HEADER_IMPORTANCE:
            importance = HEADER_IMPORTANCE[header_key]
        else:
            importance = 'low'
        
        decoded_value = decode_value(value)
        analysis['headers'][header] = {
            'value': decoded_value,
            'importance': importance
        }
        
        # Extract domains and IPs from header values
        extracted_domains = extract_domains(decoded_value)
        extracted_ips = extract_ip_addresses(decoded_value)
        
        if extracted_domains:
            analysis['headers'][header]['extracted_domains'] = extracted_domains
            analysis['summary']['domains'].update(extracted_domains)
        
        if extracted_ips:
            analysis['headers'][header]['extracted_ips'] = extracted_ips
            analysis['summary']['ip_addresses'].update(extracted_ips)
    
    # Check for missing important headers
    for important_header in ['from', 'return-path', 'received']:
        if important_header not in [h.lower() for h in analysis['headers']]:
            analysis['summary']['missing_headers'].append(important_header)
            analysis['summary']['suspicious_indicators'].append(f"Missing {important_header} header")
    
    # Analyze From and Return-Path for mismatches
    from_header = next((h for h in analysis['headers'] if h.lower() == 'from'), None)
    return_path = next((h for h in analysis['headers'] if h.lower() == 'return-path'), None)
    reply_to = next((h for h in analysis['headers'] if h.lower() == 'reply-to'), None)
    
    if from_header and return_path:
        from_email = parseaddr(analysis['headers'][from_header]['value'])[1]
        return_path_email = parseaddr(analysis['headers'][return_path]['value'])[1]
        
        # Remove angle brackets if present
        return_path_email = return_path_email.strip('<>')
        
        if from_email and return_path_email:
            from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
            return_path_domain = return_path_email.split('@')[-1].lower() if '@' in return_path_email else ''
            
            if from_domain and return_path_domain and from_domain != return_path_domain:
                analysis['summary']['mismatch_domains'] = True
                analysis['summary']['suspicious_indicators'].append(
                    f"Domain mismatch: From '{from_domain}' vs Return-Path '{return_path_domain}'"
                )
    
    # Check for Reply-To mismatches (phishing indicator)
    if from_header and reply_to:
        from_email = parseaddr(analysis['headers'][from_header]['value'])[1]
        reply_to_email = parseaddr(analysis['headers'][reply_to]['value'])[1]
        
        if from_email and reply_to_email:
            from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
            reply_to_domain = reply_to_email.split('@')[-1].lower() if '@' in reply_to_email else ''
            
            if from_domain and reply_to_domain and from_domain != reply_to_domain:
                analysis['summary']['suspicious_indicators'].append(
                    f"Reply-To mismatch: From '{from_domain}' vs Reply-To '{reply_to_domain}'"
                )
    
    # Analyze SPF, DKIM, and DMARC results if present
    authentication_results = next((h for h in analysis['headers'] if h.lower() == 'authentication-results'), None)
    
    if authentication_results:
        auth_value = analysis['headers'][authentication_results]['value']
        
        # Check SPF
        if 'spf=pass' in auth_value.lower():
            analysis['summary']['spf_result'] = 'pass'
        elif 'spf=fail' in auth_value.lower():
            analysis['summary']['spf_result'] = 'fail'
            analysis['summary']['suspicious_indicators'].append("SPF authentication failed")
        elif 'spf=neutral' in auth_value.lower():
            analysis['summary']['spf_result'] = 'neutral'
        elif 'spf=softfail' in auth_value.lower():
            analysis['summary']['spf_result'] = 'softfail'
            analysis['summary']['suspicious_indicators'].append("SPF soft-fail result")
        
        # Check DKIM
        if 'dkim=pass' in auth_value.lower():
            analysis['summary']['dkim_result'] = 'pass'
        elif 'dkim=fail' in auth_value.lower():
            analysis['summary']['dkim_result'] = 'fail'
            analysis['summary']['suspicious_indicators'].append("DKIM signature verification failed")
        
        # Check DMARC
        if 'dmarc=pass' in auth_value.lower():
            analysis['summary']['dmarc_result'] = 'pass'
        elif 'dmarc=fail' in auth_value.lower():
            analysis['summary']['dmarc_result'] = 'fail'
            analysis['summary']['suspicious_indicators'].append("DMARC check failed")
    
    # Check ARC (Authenticated Received Chain) authentication
    arc_authentication = next((h for h in analysis['headers'] if h.lower() == 'arc-authentication-results'), None)
    if arc_authentication:
        arc_value = analysis['headers'][arc_authentication]['value']
        if 'arc=pass' in arc_value.lower() or ('spf=pass' in arc_value.lower() and 'dkim=pass' in arc_value.lower()):
            analysis['summary']['arc_result'] = 'pass'
        elif 'arc=fail' in arc_value.lower():
            analysis['summary']['arc_result'] = 'fail'
            analysis['summary']['suspicious_indicators'].append("ARC authentication failed")
    
    # Look for X-Originating-IP or similar headers
    originating_ip = next((h for h in analysis['headers'] if h.lower() == 'x-originating-ip'), None)
    if originating_ip:
        analysis['summary']['has_originating_ip'] = True
    
    # Check for excessive Received headers (potential mail relaying)
    received_headers = [h for h in analysis['headers'] if h.lower() == 'received']
    if len(received_headers) > 7:  # Arbitrary threshold
        analysis['summary']['suspicious_indicators'].append(f"Excessive Received headers ({len(received_headers)})")
    
    # Advanced analysis: Check for IP reputation
    ip_addresses = list(analysis['summary']['ip_addresses'])
    for ip in ip_addresses:
        reputation = ip_reputation_check(ip)
        if reputation:
            analysis['ip_analysis'][ip] = reputation
            if reputation.get('score', 0) > 50:  # Example threshold
                analysis['summary']['suspicious_indicators'].append(
                    f"IP {ip} has poor reputation score: {reputation['score']}"
                )
    
    # Advanced analysis: Check domain reputation/age
    domains = list(analysis['summary']['domains'])
    for domain in domains:
        domain_info = domain_reputation_check(domain)
        if domain_info:
            analysis['domain_analysis'][domain] = domain_info
            if not domain_info.get('mx_records', False) and domain in analysis['summary']['domains']:
                analysis['summary']['suspicious_indicators'].append(
                    f"Domain {domain} does not have MX records"
                )
    
    # Advanced analysis: Calculate headers hash
    analysis['header_hash'] = calculate_headers_hash(analysis['headers'])
    
    # Advanced analysis: Analyze headers chronology
    analysis['chronology'] = analyze_headers_chronology(analysis['headers'])
    if analysis['chronology']['anomalies']:
        for anomaly in analysis['chronology']['anomalies']:
            analysis['summary']['suspicious_indicators'].append(f"Chronology anomaly: {anomaly}")
    
    # Advanced analysis: Extract email metadata
    analysis['metadata'] = extract_email_metadata(msg)
    
    # AI-powered analysis using OpenAI
    if openai_api_key:
        ai_analysis = analyze_ai_phishing_patterns(analysis['headers'])
        analysis['ai_analysis'] = ai_analysis
        
        # If AI analysis is available, use it to enhance threat assessment
        if ai_analysis.get('ai_analysis') and 'structured_judgment' in ai_analysis:
            judgment = ai_analysis['structured_judgment']
            
            # Add AI-identified indicators to our list
            if 'key_indicators' in judgment:
                for indicator in judgment['key_indicators']:
                    if indicator not in analysis['summary']['suspicious_indicators']:
                        analysis['summary']['suspicious_indicators'].append(f"AI-detected: {indicator}")
            
            # Update threat level based on AI risk assessment
            risk_score = judgment.get('risk_score', 0)
            if risk_score >= 7:
                ai_threat_level = 'high'
            elif risk_score >= 4:
                ai_threat_level = 'medium'
            elif risk_score >= 2:
                ai_threat_level = 'low'
            else:
                ai_threat_level = 'minimal'
                
            analysis['summary']['ai_threat_level'] = ai_threat_level
    
    # Convert sets to lists for JSON serialization
    analysis['summary']['domains'] = list(analysis['summary']['domains'])
    analysis['summary']['ip_addresses'] = list(analysis['summary']['ip_addresses'])
    
    # Make a threat assessment based on indicators
    if len(analysis['summary']['suspicious_indicators']) > 3:
        analysis['summary']['threat_level'] = 'high'
    elif len(analysis['summary']['suspicious_indicators']) > 1:
        analysis['summary']['threat_level'] = 'medium'
    elif len(analysis['summary']['suspicious_indicators']) > 0:
        analysis['summary']['threat_level'] = 'low'
    else:
        analysis['summary']['threat_level'] = 'minimal'
    
    # If we have AI analysis, combine with traditional analysis
    if 'ai_threat_level' in analysis['summary']:
        ai_level = analysis['summary']['ai_threat_level']
        traditional_level = analysis['summary']['threat_level']
        
        # Use the higher threat level of the two
        threat_levels = ['minimal', 'low', 'medium', 'high']
        ai_index = threat_levels.index(ai_level)
        traditional_index = threat_levels.index(traditional_level)
        
        if ai_index > traditional_index:
            analysis['summary']['threat_level'] = ai_level
    
    return analysis


# Flask Routes
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    # Check if a file was uploaded
    if 'email_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['email_file']
    
    # If the user didn't select a file
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze the email headers
            analysis_results = analyze_email_file(filepath)
            
            # Clean up the file
            os.remove(filepath)
            
            # Store results in session
            session['analysis_results'] = analysis_results
            
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error analyzing email: {str(e)}\n{traceback.format_exc()}")
            flash(f'Error analyzing email: {str(e)}', 'danger')
            # Clean up the file even on error
            if os.path.exists(filepath):
                os.remove(filepath)
            return redirect(url_for('index'))
    else:
        flash('Invalid file format. Please upload .eml files only.', 'danger')
        return redirect(url_for('index'))


@app.route('/results')
def results():
    analysis_results = session.get('analysis_results')
    if not analysis_results:
        flash('No analysis results found. Please upload an email file.', 'warning')
        return redirect(url_for('index'))
    
    return render_template('results.html', analysis=analysis_results)


@app.route('/reset')
def reset():
    session.pop('analysis_results', None)
    return redirect(url_for('index'))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic analysis"""
    if 'email_file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['email_file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze the email headers
            analysis_results = analyze_email_file(filepath)
            
            # Clean up the file
            os.remove(filepath)
            
            return jsonify(analysis_results)
        except Exception as e:
            logging.error(f"API error analyzing email: {str(e)}\n{traceback.format_exc()}")
            # Clean up the file even on error
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file format. Please upload .eml files only.'}), 400


# HTML Template Content
HTML_TEMPLATES = {
    # Layout template
    'layout.html': '''
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Email Header Analyzer</title>
    <!-- Replit-themed Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* Custom styles for Email Header Analyzer */
        /* Improve header value readability */
        .header-value {
            word-break: break-word;
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        /* Make cards the same height in a row */
        .card-deck .card {
            display: flex;
            flex-direction: column;
        }
        
        /* Add some spacing and styling to the main container */
        .container {
            padding-top: 1rem;
            padding-bottom: 1rem;
        }
        
        /* Style for file upload area */
        .custom-file-label {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        /* Footer styling */
        .footer {
            position: absolute;
            bottom: 0;
            width: 100%;
            height: 60px;
            line-height: 60px;
        }
        
        /* Ensure content doesn't go under footer */
        body {
            margin-bottom: 60px;
            min-height: 100vh;
            position: relative;
            padding-bottom: 60px;
        }
        
        /* Badge styling */
        .badge {
            font-weight: 500;
        }
        
        /* Improve table readability */
        .table-responsive {
            max-height: 600px;
            overflow-y: auto;
        }
        
        /* Add borders to accordion items */
        .accordion-item {
            border: 1px solid var(--bs-gray-400);
            margin-bottom: 0.5rem;
        }
        
        /* Add hover effect to cards */
        .card {
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        
        /* Custom scrollbar for better visibility */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bs-gray-800);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--bs-gray-600);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--bs-gray-500);
        }
        
        /* AI Analysis section styling */
        .ai-analysis {
            border-left: 4px solid var(--bs-purple);
            padding-left: 1rem;
            margin-bottom: 1.5rem;
        }
        
        /* Timeline visualization */
        .timeline {
            position: relative;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .timeline::after {
            content: '';
            position: absolute;
            width: 6px;
            background-color: var(--bs-gray-700);
            top: 0;
            bottom: 0;
            left: 50%;
            margin-left: -3px;
        }
        
        .timeline-container {
            padding: 10px 40px;
            position: relative;
            background-color: inherit;
            width: 50%;
        }
        
        .timeline-container::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            right: -10px;
            background-color: var(--bs-dark);
            border: 4px solid var(--bs-purple);
            top: 15px;
            border-radius: 50%;
            z-index: 1;
        }
        
        .left {
            left: 0;
        }
        
        .right {
            left: 50%;
        }
        
        .left::before {
            content: " ";
            height: 0;
            position: absolute;
            top: 22px;
            width: 0;
            z-index: 1;
            right: 30px;
            border: medium solid var(--bs-gray-700);
            border-width: 10px 0 10px 10px;
            border-color: transparent transparent transparent var(--bs-gray-700);
        }
        
        .right::before {
            content: " ";
            height: 0;
            position: absolute;
            top: 22px;
            width: 0;
            z-index: 1;
            left: 30px;
            border: medium solid var(--bs-gray-700);
            border-width: 10px 10px 10px 0;
            border-color: transparent var(--bs-gray-700) transparent transparent;
        }
        
        .right::after {
            left: -10px;
        }
        
        .timeline-content {
            padding: 20px 30px;
            background-color: var(--bs-gray-800);
            position: relative;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt me-2"></i>Email Header Analyzer
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/reset">New Analysis</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="container mb-5">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </main>

    <footer class="footer mt-auto py-3 bg-dark">
        <div class="container text-center">
            <span class="text-muted">Email Header Analyzer - © 2025</span>
        </div>
    </footer>

    <!-- Bootstrap JavaScript Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Chart.js for visualizations -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    {% block scripts %}{% endblock %}
</body>
</html>
''',

    # Index template
    'index.html': '''
{% extends "layout.html" %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-10 col-lg-8">
        <div class="card shadow border-0">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-envelope me-2"></i>Analyze Email Headers</h4>
            </div>
            <div class="card-body">
                <p class="lead">This tool analyzes email headers to help detect potential spoofing and security threats. Upload an email file (.eml) to begin.</p>
                
                <div class="alert alert-info" role="alert">
                    <h5 class="alert-heading"><i class="fas fa-info-circle me-2"></i>How to use this tool:</h5>
                    <ol>
                        <li>Save your email as a .eml file (most email clients support this)</li>
                        <li>Upload the file using the form below</li>
                        <li>Review the detailed analysis results</li>
                    </ol>
                </div>
                
                <hr>
                
                <form action="{{ url_for('analyze') }}" method="POST" enctype="multipart/form-data">
                    <div class="mb-4">
                        <label for="email_file" class="form-label"><i class="fas fa-file-upload me-2"></i>Upload Email File (.eml)</label>
                        <input class="form-control form-control-lg" type="file" id="email_file" name="email_file" accept=".eml,.msg">
                        <div class="form-text">Maximum file size: 10MB</div>
                    </div>
                    
                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-lg btn-primary">
                            <i class="fas fa-search me-2"></i>Analyze Headers
                        </button>
                    </div>
                </form>
            </div>
            <div class="card-footer">
                <div class="mb-3">
                    <h5><i class="fas fa-shield-alt me-2"></i>Advanced Security Checks:</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>SPF Validation</li>
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>DKIM Verification</li>
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>DMARC Compliance</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>AI-Powered Threat Detection</li>
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>Header Chronology Analysis</li>
                                <li class="list-group-item bg-transparent"><i class="fas fa-check-circle text-success me-2"></i>Domain & IP Reputation</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
''',

    # Results template
    'results.html': '''
{% extends "layout.html" %}
{% block content %}
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow border-0">
            <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h4 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Analysis Summary</h4>
                <a href="{{ url_for('reset') }}" class="btn btn-outline-light btn-sm">
                    <i class="fas fa-redo me-1"></i>New Analysis
                </a>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3 h-100" style="border-left: 5px solid 
                            {% if analysis.summary.threat_level == 'high' %}var(--bs-danger){% elif analysis.summary.threat_level == 'medium' %}var(--bs-warning){% elif analysis.summary.threat_level == 'low' %}var(--bs-info){% else %}var(--bs-success){% endif %};
                        ">
                            <div class="card-body">
                                <h5 class="card-title">Threat Assessment</h5>
                                <div class="d-flex align-items-center mb-3">
                                    <div class="me-3">
                                        <span class="display-5">
                                            {% if analysis.summary.threat_level == 'high' %}
                                                <i class="fas fa-exclamation-triangle text-danger"></i>
                                            {% elif analysis.summary.threat_level == 'medium' %}
                                                <i class="fas fa-exclamation-circle text-warning"></i>
                                            {% elif analysis.summary.threat_level == 'low' %}
                                                <i class="fas fa-info-circle text-info"></i>
                                            {% else %}
                                                <i class="fas fa-check-circle text-success"></i>
                                            {% endif %}
                                        </span>
                                    </div>
                                    <div>
                                        <h2 class="mb-0 text-capitalize">
                                            {% if analysis.summary.threat_level == 'high' %}
                                                <span class="text-danger">{{ analysis.summary.threat_level }}</span>
                                            {% elif analysis.summary.threat_level == 'medium' %}
                                                <span class="text-warning">{{ analysis.summary.threat_level }}</span>
                                            {% elif analysis.summary.threat_level == 'low' %}
                                                <span class="text-info">{{ analysis.summary.threat_level }}</span>
                                            {% else %}
                                                <span class="text-success">{{ analysis.summary.threat_level }}</span>
                                            {% endif %}
                                        </h2>
                                        <p class="text-muted mb-0">Threat Level</p>
                                    </div>
                                </div>
                                
                                {% if analysis.ai_analysis and analysis.ai_analysis.ai_analysis and analysis.ai_analysis.structured_judgment %}
                                    <div class="alert alert-secondary">
                                        <h6 class="alert-heading"><i class="fas fa-robot me-2"></i>AI Confidence Score:</h6>
                                        <div class="progress mb-2" style="height: 20px;">
                                            <div class="progress-bar bg-primary" role="progressbar" 
                                                style="width: {{ (analysis.ai_analysis.structured_judgment.confidence * 100)|int }}%" 
                                                aria-valuenow="{{ (analysis.ai_analysis.structured_judgment.confidence * 100)|int }}" 
                                                aria-valuemin="0" 
                                                aria-valuemax="100">
                                                {{ (analysis.ai_analysis.structured_judgment.confidence * 100)|int }}%
                                            </div>
                                        </div>
                                    </div>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card mb-3 h-100">
                            <div class="card-body">
                                <h5 class="card-title">Authentication Status</h5>
                                <div class="row text-center">
                                    <div class="col-4">
                                        <div class="p-3">
                                            <h5>SPF</h5>
                                            {% if analysis.summary.spf_result == 'pass' %}
                                                <i class="fas fa-check-circle text-success fa-2x"></i>
                                                <p class="mb-0 mt-2 text-success">Pass</p>
                                            {% elif analysis.summary.spf_result == 'neutral' %}
                                                <i class="fas fa-minus-circle text-warning fa-2x"></i>
                                                <p class="mb-0 mt-2 text-warning">Neutral</p>
                                            {% elif analysis.summary.spf_result == 'softfail' %}
                                                <i class="fas fa-exclamation-circle text-warning fa-2x"></i>
                                                <p class="mb-0 mt-2 text-warning">SoftFail</p>
                                            {% elif analysis.summary.spf_result == 'fail' %}
                                                <i class="fas fa-times-circle text-danger fa-2x"></i>
                                                <p class="mb-0 mt-2 text-danger">Fail</p>
                                            {% else %}
                                                <i class="fas fa-question-circle text-muted fa-2x"></i>
                                                <p class="mb-0 mt-2 text-muted">Unknown</p>
                                            {% endif %}
                                        </div>
                                    </div>
                                    <div class="col-4">
                                        <div class="p-3">
                                            <h5>DKIM</h5>
                                            {% if analysis.summary.dkim_result == 'pass' %}
                                                <i class="fas fa-check-circle text-success fa-2x"></i>
                                                <p class="mb-0 mt-2 text-success">Pass</p>
                                            {% elif analysis.summary.dkim_result == 'fail' %}
                                                <i class="fas fa-times-circle text-danger fa-2x"></i>
                                                <p class="mb-0 mt-2 text-danger">Fail</p>
                                            {% else %}
                                                <i class="fas fa-question-circle text-muted fa-2x"></i>
                                                <p class="mb-0 mt-2 text-muted">Unknown</p>
                                            {% endif %}
                                        </div>
                                    </div>
                                    <div class="col-4">
                                        <div class="p-3">
                                            <h5>DMARC</h5>
                                            {% if analysis.summary.dmarc_result == 'pass' %}
                                                <i class="fas fa-check-circle text-success fa-2x"></i>
                                                <p class="mb-0 mt-2 text-success">Pass</p>
                                            {% elif analysis.summary.dmarc_result == 'fail' %}
                                                <i class="fas fa-times-circle text-danger fa-2x"></i>
                                                <p class="mb-0 mt-2 text-danger">Fail</p>
                                            {% else %}
                                                <i class="fas fa-question-circle text-muted fa-2x"></i>
                                                <p class="mb-0 mt-2 text-muted">Unknown</p>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-12">
                        {% if analysis.summary.suspicious_indicators %}
                            <div class="card mb-4">
                                <div class="card-header bg-warning text-dark">
                                    <h5 class="mb-0"><i class="fas fa-exclamation-triangle me-2"></i>Suspicious Indicators</h5>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group">
                                        {% for indicator in analysis.summary.suspicious_indicators %}
                                            <li class="list-group-item bg-transparent">
                                                <i class="fas fa-exclamation-circle text-warning me-2"></i>{{ indicator }}
                                            </li>
                                        {% endfor %}
                                    </ul>
                                </div>
                            </div>
                        {% endif %}
                    </div>
                </div>
                
                {% if analysis.ai_analysis and analysis.ai_analysis.ai_analysis and analysis.ai_analysis.detailed_analysis %}
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="card mb-4">
                                <div class="card-header bg-purple text-white" style="background-color: var(--bs-purple);">
                                    <h5 class="mb-0"><i class="fas fa-brain me-2"></i>AI-Powered Analysis</h5>
                                </div>
                                <div class="card-body">
                                    <div class="ai-analysis">
                                        {{ analysis.ai_analysis.detailed_analysis|replace('\n', '<br>')|safe }}
                                    </div>
                                    
                                    {% if analysis.ai_analysis.structured_judgment and analysis.ai_analysis.structured_judgment.recommendations %}
                                        <div class="mt-4">
                                            <h5><i class="fas fa-shield-alt me-2"></i>Security Recommendations:</h5>
                                            <ul class="list-group">
                                                {% for recommendation in analysis.ai_analysis.structured_judgment.recommendations %}
                                                    <li class="list-group-item bg-transparent">
                                                        <i class="fas fa-check-circle text-success me-2"></i>{{ recommendation }}
                                                    </li>
                                                {% endfor %}
                                            </ul>
                                        </div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<!-- Domains and IP Addresses -->
<div class="row mb-4">
    <div class="col-md-6">
        <div class="card shadow border-0 h-100">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0"><i class="fas fa-globe me-2"></i>Domains ({{ analysis.summary.domains|length }})</h5>
            </div>
            <div class="card-body">
                {% if analysis.summary.domains %}
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>MX Records</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for domain in analysis.summary.domains %}
                                    <tr>
                                        <td>{{ domain }}</td>
                                        <td>
                                            {% if domain in analysis.domain_analysis and analysis.domain_analysis[domain].mx_records %}
                                                <span class="badge bg-success">Valid</span>
                                            {% else %}
                                                <span class="badge bg-warning">Missing</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="alert alert-info">No domains found in the email headers.</div>
                {% endif %}
                
                {% if analysis.summary.mismatch_domains %}
                    <div class="alert alert-danger mt-3">
                        <i class="fas fa-exclamation-triangle me-2"></i>Domain mismatch detected between From and Return-Path headers!
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card shadow border-0 h-100">
            <div class="card-header bg-secondary text-white">
                <h5 class="mb-0"><i class="fas fa-network-wired me-2"></i>IP Addresses ({{ analysis.summary.ip_addresses|length }})</h5>
            </div>
            <div class="card-body">
                {% if analysis.summary.ip_addresses %}
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Reputation</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for ip in analysis.summary.ip_addresses %}
                                    <tr>
                                        <td>{{ ip }}</td>
                                        <td>
                                            {% if ip in analysis.ip_analysis %}
                                                {% if analysis.ip_analysis[ip].score < 25 %}
                                                    <span class="badge bg-success">Good</span>
                                                {% elif analysis.ip_analysis[ip].score < 75 %}
                                                    <span class="badge bg-warning">Moderate</span>
                                                {% else %}
                                                    <span class="badge bg-danger">Poor</span>
                                                {% endif %}
                                            {% else %}
                                                <span class="badge bg-secondary">Unknown</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="alert alert-info">No IP addresses found in the email headers.</div>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<!-- Chronology Analysis -->
{% if analysis.chronology and analysis.chronology.timeline %}
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow border-0">
            <div class="card-header bg-dark text-white">
                <h5 class="mb-0"><i class="fas fa-history me-2"></i>Email Routing Timeline</h5>
            </div>
            <div class="card-body">
                <div class="timeline-container px-4">
                    {% for item in analysis.chronology.timeline %}
                        <div class="mb-3 p-3 border {% if loop.index % 2 == 0 %}border-info{% else %}border-primary{% endif %} rounded">
                            <div class="d-flex justify-content-between">
                                <h6 class="mb-2">{{ item.timestamp.strftime('%Y-%m-%d %H:%M:%S') if item.timestamp else 'Unknown' }}</h6>
                                <span class="badge {% if loop.index % 2 == 0 %}bg-info{% else %}bg-primary{% endif %}">Hop {{ loop.index }}</span>
                            </div>
                            <p class="mb-0 small text-muted">{{ item.value }}</p>
                        </div>
                    {% endfor %}
                </div>
                
                {% if analysis.chronology.anomalies %}
                    <div class="alert alert-warning mt-4">
                        <h6 class="alert-heading"><i class="fas fa-exclamation-triangle me-2"></i>Timeline Anomalies:</h6>
                        <ul class="mb-0">
                            {% for anomaly in analysis.chronology.anomalies %}
                                <li>{{ anomaly }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endif %}

<!-- Email Client Metadata -->
{% if analysis.metadata %}
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow border-0">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i>Email Metadata</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <table class="table">
                            <tbody>
                                <tr>
                                    <th>Email Client:</th>
                                    <td>{{ analysis.metadata.client_info or 'Unknown' }}</td>
                                </tr>
                                <tr>
                                    <th>Languages:</th>
                                    <td>
                                        {% if analysis.metadata.languages %}
                                            {% for lang in analysis.metadata.languages %}
                                                <span class="badge bg-info me-1">{{ lang }}</span>
                                            {% endfor %}
                                        {% else %}
                                            None detected
                                        {% endif %}
                                    </td>
                                </tr>
                                <tr>
                                    <th>Has Attachments:</th>
                                    <td>
                                        {% if analysis.metadata.has_attachments %}
                                            <span class="badge bg-warning">Yes</span>
                                        {% else %}
                                            <span class="badge bg-success">No</span>
                                        {% endif %}
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table">
                            <tbody>
                                <tr>
                                    <th>Content Types:</th>
                                    <td>
                                        {% if analysis.metadata.content_types %}
                                            {% for type in analysis.metadata.content_types %}
                                                <span class="badge bg-secondary me-1">{{ type }}</span>
                                            {% endfor %}
                                        {% else %}
                                            None detected
                                        {% endif %}
                                    </td>
                                </tr>
                                <tr>
                                    <th>URLs in Content:</th>
                                    <td>{{ analysis.metadata.urls|length or 0 }}</td>
                                </tr>
                                <tr>
                                    <th>Fingerprint:</th>
                                    <td><code>{{ analysis.header_hash[:10] }}...</code></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                {% if analysis.metadata.urls %}
                    <div class="mt-4">
                        <h6><i class="fas fa-link me-2"></i>Detected URLs:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm table-hover">
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>URL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for url in analysis.metadata.urls %}
                                        <tr>
                                            <td>{{ loop.index }}</td>
                                            <td><code>{{ url }}</code></td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endif %}

<!-- Raw Headers -->
<div class="row mb-4">
    <div class="col-12">
        <div class="accordion" id="headerAccordion">
            <div class="accordion-item">
                <h2 class="accordion-header" id="headingOne">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseHeaders" aria-expanded="false" aria-controls="collapseHeaders">
                        <i class="fas fa-code me-2"></i>Raw Headers ({{ analysis.headers|length }})
                    </button>
                </h2>
                <div id="collapseHeaders" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#headerAccordion">
                    <div class="accordion-body p-0">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th style="width: 20%;">Header</th>
                                        <th>Value</th>
                                        <th style="width: 15%;">Importance</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for header, data in analysis.headers.items() %}
                                        <tr>
                                            <td class="fw-bold">{{ header }}</td>
                                            <td class="header-value">{{ data.value }}</td>
                                            <td>
                                                {% if data.importance == 'critical' %}
                                                    <span class="badge bg-danger">Critical</span>
                                                {% elif data.importance == 'high' %}
                                                    <span class="badge bg-warning">High</span>
                                                {% elif data.importance == 'medium' %}
                                                    <span class="badge bg-info">Medium</span>
                                                {% else %}
                                                    <span class="badge bg-secondary">Low</span>
                                                {% endif %}
                                            </td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        })
    });
</script>
{% endblock %}
'''
}


class StringTemplateLoader(object):
    def __init__(self, templates):
        self.templates = templates
        
    def get_source(self, environment, template):
        if template in self.templates:
            source = self.templates[template]
            return source, None, lambda: True
        raise TemplateNotFound(template)
    
    def list_templates(self):
        return list(self.templates.keys())


app.jinja_loader = StringTemplateLoader(HTML_TEMPLATES)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
