#!/usr/bin/env python3
import email
import json
import os
import re
import base64
import random
from datetime import datetime
from email import policy
from email.utils import parseaddr, formataddr, parsedate_to_datetime
import uuid
import html
from pathlib import Path

# Constants for random selection
SPF_DKIM_VALUES = ["pass", "fail", "none", "neutral"]
DMARC_VALUES = ["pass", "fail", "none"]
IP_ADDRESSES = [
    "2603:1096:c01:19c::",
    "2603:1096:a01:af::",
    "2603:1096:a01:af:cafe::",
    "2a01:111:f403:c409::",
    "2603:1096:a04::",
    "2603:1096:c01:ec::",
    "2603:1096:a01:1c7::",
    "fe80::"
]


def validate_and_fix_email(email_str):
    """Validate and fix email addresses"""
    if not email_str:
        return ""
    
    # Parse email address
    name, addr = parseaddr(email_str)
    
    # Basic email validation pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # If the address part is valid, return it
    if addr and re.match(email_pattern, addr):
        return addr
    
    # Try to extract email from the string
    email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email_str)
    if email_match:
        return email_match.group(0)
    
    # If no valid email found, return the original (will need manual correction)
    return email_str.strip()


def extract_email_addresses(header_value):
    """Extract email addresses from header value"""
    if not header_value:
        return []
    
    addresses = []
    # Handle multiple addresses separated by comma
    for addr in header_value.split(','):
        email_addr = validate_and_fix_email(addr.strip())
        if email_addr:
            addresses.append({
                "emailAddress": {
                    "name": "",
                    "address": email_addr
                }
            })
    return addresses


def extract_html_text(html_content):
    """Extract text from HTML content"""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', html_content)
    # Decode HTML entities
    text = html.unescape(text)
    # Clean up whitespace
    text = ' '.join(text.split())
    return text


def extract_links_from_html(html_content):
    """Extract all links from HTML content"""
    links = []
    # Find all href attributes
    href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
    matches = re.findall(href_pattern, html_content, re.IGNORECASE)
    
    for link in matches:
        # Decode HTML entities in URLs
        link = html.unescape(link)
        if link and (link.startswith('http://') or link.startswith('https://')):
            links.append(link)
    
    return links


def extract_domains_from_links(links):
    """Extract unique domains from links"""
    domains = set()
    for link in links:
        # Extract domain from URL
        domain_match = re.match(r'https?://([^/]+)', link)
        if domain_match:
            domain = domain_match.group(0)
            domains.add(domain)
    
    return list(domains)


def parse_eml_to_json(eml_path, tenant_id="2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a"):
    """Parse EML file and convert to required JSON format"""
    # Try to parse with default policy first, then fallback to compat32
    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.compat32)
    
    # Extract basic information
    subject = msg.get('Subject', '')
    from_header = msg.get('From', '')
    to_header = msg.get('To', '')
    cc_header = msg.get('Cc', '')
    bcc_header = msg.get('Bcc', '')
    reply_to_header = msg.get('Reply-To', '')
    message_id = msg.get('Message-ID', f'<{uuid.uuid4()}@generated>')
    
    # Extract and validate sender email
    sender_email = validate_and_fix_email(from_header)
    
    # Extract return path, use sender email if not available
    return_path = msg.get('Return-Path', '')
    if return_path:
        return_path = validate_and_fix_email(return_path)
    else:
        return_path = sender_email
    
    # Extract recipients
    to_recipients = extract_email_addresses(to_header)
    cc_recipients = extract_email_addresses(cc_header)
    bcc_recipients = extract_email_addresses(bcc_header)
    reply_to_recipients = extract_email_addresses(reply_to_header)
    
    # Use first TO recipient as mailbox_id, or sender if no TO recipients
    mailbox_id = to_recipients[0]['emailAddress']['address'] if to_recipients else sender_email
    
    # Extract dates
    date_header = msg.get('Date', '')
    try:
        email_date = parsedate_to_datetime(date_header)
        date_str = email_date.isoformat()
    except:
        date_str = datetime.now().isoformat()
    
    # Extract body
    body_content = ""
    content_type = "text"
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                try:
                    body_content = part.get_content()
                except:
                    body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                content_type = "html"
                break
            elif part.get_content_type() == 'text/plain' and not body_content:
                try:
                    body_content = part.get_content()
                except:
                    body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                content_type = "text"
    else:
        try:
            body_content = msg.get_content()
        except:
            body_content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        if msg.get_content_type() == 'text/html':
            content_type = "html"
    
    # Extract links and domains if HTML content
    links = []
    domains = []
    plain_text_content = body_content
    
    if content_type == "html":
        links = extract_links_from_html(body_content)
        domains = extract_domains_from_links(links)
        plain_text_content = extract_html_text(body_content)
    
    # Extract attachments
    has_attachments = False
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            # Check for attachments or inline images/files
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            
            # Include attachments and inline images/files (not text/html or text/plain)
            if (content_disposition == 'attachment' or 
                (content_disposition == 'inline' and not content_type.startswith('text/')) or
                (content_type.startswith('image/') and part.get_filename())):
                has_attachments = True
                
                # Get attachment details
                filename = part.get_filename()
                if filename:
                    # Get content type
                    content_type = part.get_content_type()
                    
                    # Get attachment content as base64
                    try:
                        # Get transfer encoding
                        transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()
                        
                        if transfer_encoding == 'base64':
                            # Content is already base64 encoded
                            content = part.get_payload()
                            # Remove any whitespace/newlines
                            if isinstance(content, str):
                                content = content.replace('\n', '').replace('\r', '').strip()
                        else:
                            # Decode and re-encode as base64
                            raw_content = part.get_payload(decode=True)
                            if raw_content:
                                content = base64.b64encode(raw_content).decode('utf-8')
                            else:
                                content = ""
                    except Exception as e:
                        # Fallback: try to get content as is
                        try:
                            content = part.get_payload()
                            if not isinstance(content, str):
                                content = base64.b64encode(content).decode('utf-8')
                        except:
                            content = ""
                    
                    attachments.append({
                        "name": filename,
                        "contentBytes": content,
                        "contentType": content_type
                    })
    
    # Extract SPF, DKIM, DMARC from headers (if available)
    auth_results = msg.get('Authentication-Results', '')
    spf_result = None
    dkim_result = None
    dmarc_result = None
    
    if auth_results:
        # Check for SPF
        if 'spf=pass' in auth_results:
            spf_result = "pass"
        elif 'spf=fail' in auth_results:
            spf_result = "fail"
        elif 'spf=neutral' in auth_results:
            spf_result = "neutral"
        elif 'spf=none' in auth_results:
            spf_result = "none"
        
        # Check for DKIM
        if 'dkim=pass' in auth_results:
            dkim_result = "pass"
        elif 'dkim=fail' in auth_results:
            dkim_result = "fail"
        elif 'dkim=neutral' in auth_results:
            dkim_result = "neutral"
        elif 'dkim=none' in auth_results:
            dkim_result = "none"
        
        # Check for DMARC
        if 'dmarc=pass' in auth_results:
            dmarc_result = "pass"
        elif 'dmarc=fail' in auth_results:
            dmarc_result = "fail"
        elif 'dmarc=none' in auth_results:
            dmarc_result = "none"
    
    # Use random values if not found in headers
    if spf_result is None:
        spf_result = random.choice(SPF_DKIM_VALUES)
    if dkim_result is None:
        dkim_result = random.choice(SPF_DKIM_VALUES)
    if dmarc_result is None:
        dmarc_result = random.choice(DMARC_VALUES)
    
    # Extract IP address from Received headers or use random
    ip_address = None
    received_headers = msg.get_all('Received', [])
    for received in received_headers:
        # Look for IP addresses in brackets
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
        if not ip_match:
            # Look for IPv6 addresses
            ip_match = re.search(r'\[([0-9a-fA-F:]+)\]', received)
        if ip_match:
            ip_address = ip_match.group(1)
            break
    
    # Use random IP if not found
    if not ip_address:
        ip_address = random.choice(IP_ADDRESSES)
    
    # Create unique message ID with test-malicious format
    filename_without_ext = os.path.splitext(os.path.basename(eml_path))[0]
    unique_id = f"test-malicious-{filename_without_ext}"
    
    # Build the JSON structure
    json_data = {
        "tenant_id": tenant_id,
        "mailbox_id": mailbox_id,
        "message_id": unique_id,
        "force_override": True,
        "test_mode": True,
        "email_data": {
            "id": unique_id,
            "emailcontent": {
                "subject": subject,
                "sender": {
                    "emailAddress": {
                        "name": "",
                        "address": sender_email
                    }
                },
                "from": {
                    "emailAddress": {
                        "name": "",
                        "address": sender_email
                    }
                },
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients,
                "bccRecipients": bcc_recipients,
                "replyTo": reply_to_recipients,
                "receivedDateTime": date_str,
                "sentDateTime": date_str,
                "body": {
                    "contentType": content_type,
                    "content": body_content
                },
                "hasAttachments": has_attachments,
                "internetMessageId": message_id,
                "importance": "normal",
                "isRead": False,
                "isDraft": False,
                "flag": {
                    "flagStatus": "notFlagged"
                }
            },
            "headers": {
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result,
                "returnpath": return_path,
                "ipaddress": [ip_address],
                "smtpserver": "PN2P287MB0160.INDP287.PROD.OUTLOOK.COM",
                "tlsversion": "not available",
                "list_unsubscribe_urls": [],
                "list_unsubscribe_mailtos": [],
                "list_unsubscribe_one_click": False
            },
            "payload": {
                "content": plain_text_content[:500] if plain_text_content else "",  # First 500 chars
                "links": links,
                "domains": domains
            }
        }
    }
    
    # Add attachments to the JSON if present
    if attachments:
        json_data["email_data"]["attachments"] = attachments
    
    return json_data


def main():
    """Main function to process all EML files"""
    # Get the folder path from user or use current directory
    folder_path = input("Enter the folder path containing EML files (press Enter for current directory): ").strip()
    if not folder_path:
        folder_path = os.getcwd()
    
    # Validate folder exists
    if not os.path.exists(folder_path):
        print(f"Error: Folder '{folder_path}' does not exist!")
        return
    
    # Create output directory
    output_dir = os.path.join(os.getcwd(), "converted_emails")
    os.makedirs(output_dir, exist_ok=True)
    print(f"Output directory created: {output_dir}")
    
    # Process all EML files
    eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.eml')]
    
    if not eml_files:
        print("No EML files found in the specified folder!")
        return
    
    print(f"Found {len(eml_files)} EML files to process...")
    
    successful = 0
    failed = 0
    files_with_attachments = []
    
    for eml_file in eml_files:
        try:
            print(f"Processing: {eml_file}")
            eml_path = os.path.join(folder_path, eml_file)
            
            # Convert EML to JSON
            json_data = parse_eml_to_json(eml_path)
            
            # Save JSON file with message_id as filename
            json_filename = json_data['message_id'] + '.json'
            json_path = os.path.join(output_dir, json_filename)
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            successful += 1
            
            # Check if file has attachments
            if 'attachments' in json_data.get('email_data', {}):
                files_with_attachments.append((eml_file, json_filename))
                print(f"  ✓ Converted successfully: {json_filename} (Has {len(json_data['email_data']['attachments'])} attachment(s))")
            else:
                print(f"  ✓ Converted successfully: {json_filename}")
            
        except Exception as e:
            failed += 1
            print(f"  ✗ Failed to convert {eml_file}: {str(e)}")
    
    print(f"\nConversion complete!")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Output files saved in: {output_dir}")
    
    # Print attachment summary
    if files_with_attachments:
        print(f"\nFiles with attachments: {len(files_with_attachments)}")
        for eml_name, json_name in files_with_attachments:
            print(f"  - {eml_name} → {json_name}")
    else:
        print("\nNo files with attachments found.")


if __name__ == "__main__":
    main()