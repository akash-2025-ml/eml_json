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
    "91.250.83.70",
    "192.99.16.53",
    "65.254.247.224",
    "105.19.49.175",
    "208.109.62.199",
    "91.250.83.70",
]


def generate_random_email():
    """Generate a random unique email address"""
    import string

    # Generate random username components
    # Random first name (5-8 characters)
    first_part = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 8)))

    # Random number or middle part
    middle_options = [
        "".join(
            random.choices(string.digits, k=random.randint(2, 4))
        ),  # numbers like 23, 456, 8901
        "".join(
            random.choices(string.ascii_lowercase, k=random.randint(3, 5))
        ),  # letters
        "_"
        + "".join(
            random.choices(string.ascii_lowercase, k=random.randint(3, 5))
        ),  # with underscore
        "."
        + "".join(
            random.choices(string.ascii_lowercase, k=random.randint(3, 5))
        ),  # with dot
        "",  # sometimes no middle part
    ]
    middle_part = random.choice(middle_options)

    # Random last part (optional)
    if random.random() > 0.5:
        last_part = random.choice(
            ["", "_" + str(random.randint(1, 999)), str(random.randint(1970, 2025))]
        )
    else:
        last_part = ""

    # Combine username parts
    username = first_part + middle_part + last_part

    # Generate random domain
    domain_names = [
        "".join(
            random.choices(string.ascii_lowercase, k=random.randint(4, 8))
        ),  # random domain
        random.choice(
            [
                "mail",
                "email",
                "web",
                "net",
                "online",
                "digital",
                "tech",
                "cloud",
                "cyber",
                "data",
            ]
        )
        + random.choice(["box", "hub", "zone", "spot", "link", "base", "core", ""]),
    ]

    domain_name = random.choice(domain_names)

    # Random TLD
    common_tlds = [
        "com",
        "net",
        "org",
        "io",
        "co",
        "info",
        "biz",
        "me",
        "email",
        "online",
    ]
    regional_tlds = ["us", "uk", "ca", "au", "de", "fr", "jp", "in", "br", "mx"]
    compound_tlds = ["co.uk", "co.jp", "co.in", "com.au", "com.br", "org.uk"]

    # Weight towards common TLDs
    tld_choice = random.random()
    if tld_choice < 0.7:
        tld = random.choice(common_tlds)
    elif tld_choice < 0.85:
        tld = random.choice(regional_tlds)
    else:
        tld = random.choice(compound_tlds)

    # Final email
    email = f"{username}@{domain_name}.{tld}"

    # Ensure valid email format
    email = (
        email.replace("..", ".")
        .replace("__", "_")
        .replace("-.", ".")
        .replace(".-", ".")
    )

    return email.lower()


def validate_and_fix_email(email_str):
    """Validate and fix email addresses"""
    if not email_str:
        return ""

    # First, try using parseaddr
    name, addr = parseaddr(email_str)

    # Enhanced email validation pattern that handles more cases
    # This pattern handles:
    # - Standard emails: user@domain.com
    # - Emails with dots: user.name@domain.com
    # - Emails with special chars: user+tag@domain.com
    # - Emails with underscores: user_name@domain.com
    # - Emails with hyphens: user-name@domain.com
    # - Domains with multiple dots: user@mail.domain.co.uk
    email_pattern = (
        r"^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$"
    )

    # If parseaddr found a valid address, validate and return it
    if addr and re.match(email_pattern, addr):
        return addr.lower()  # Normalize to lowercase

    # Clean the input string
    email_str = email_str.strip()

    # Remove angle brackets if present
    email_str = re.sub(r"[<>]", "", email_str)

    # Remove quotes if present
    email_str = email_str.strip("\"'")

    # Try to extract email from the string with a more flexible pattern
    # This pattern is more forgiving and tries to find anything that looks like an email
    email_patterns = [
        r"([a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})",
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        r"([\w\.-]+@[\w\.-]+\.[\w]+)",
    ]

    for pattern in email_patterns:
        email_match = re.search(pattern, email_str, re.IGNORECASE)
        if email_match:
            extracted_email = email_match.group(1).lower()
            # Final validation
            if re.match(email_pattern, extracted_email):
                return extracted_email

    # Handle special cases like "email at domain dot com"
    # Convert common obfuscations
    email_str = re.sub(r"\s+at\s+", "@", email_str, flags=re.IGNORECASE)
    email_str = re.sub(r"\s+dot\s+", ".", email_str, flags=re.IGNORECASE)
    email_str = re.sub(r"\[at\]", "@", email_str, flags=re.IGNORECASE)
    email_str = re.sub(r"\[dot\]", ".", email_str, flags=re.IGNORECASE)
    email_str = re.sub(r"\s+", "", email_str)  # Remove all spaces

    # Try again after deobfuscation
    if re.match(email_pattern, email_str):
        return email_str.lower()

    # If still no valid email found, return empty string instead of invalid data
    # This prevents invalid email addresses in the output
    return ""


def extract_email_addresses(header_value):
    """Extract email addresses from header value"""
    if not header_value:
        return []

    addresses = []

    # First try to use parseaddr for each address
    # Some headers might have semicolon-separated addresses
    header_value = header_value.replace(";", ",")

    # Split by comma but be careful with commas inside quotes
    # Use a simple approach: if we have quotes, handle them specially
    if '"' in header_value:
        # Complex parsing for quoted names
        parts = []
        current = []
        in_quotes = False
        for char in header_value:
            if char == '"':
                in_quotes = not in_quotes
            if char == "," and not in_quotes:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)
        if current:
            parts.append("".join(current))
    else:
        # Simple split by comma
        parts = header_value.split(",")

    # Process each part
    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Try to extract name and email
        name, email_addr = parseaddr(part)

        # If parseaddr didn't find an email, try our validator
        if not email_addr:
            email_addr = validate_and_fix_email(part)
        else:
            # Validate the email parseaddr found
            email_addr = validate_and_fix_email(email_addr)

        if email_addr:
            addresses.append(
                {
                    "emailAddress": {
                        "name": name.strip() if name else "",
                        "address": email_addr,
                    }
                }
            )

    return addresses


def extract_html_text(html_content):
    """Extract text from HTML content"""
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", html_content)
    # Decode HTML entities
    text = html.unescape(text)
    # Clean up whitespace
    text = " ".join(text.split())
    return text


def extract_links_from_content(content):
    """Extract all links from HTML or text content"""
    links = []
    seen_links = set()  # To avoid duplicates

    # Decode HTML entities first
    content = html.unescape(content)

    # Pattern 1: Find all href attributes in HTML
    href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
    href_matches = re.findall(href_pattern, content, re.IGNORECASE)

    # Pattern 2: Find URLs in plain text (more comprehensive)
    # This pattern finds URLs with or without protocol
    url_patterns = [
        # Standard URLs with protocol
        r'(https?://[^\s<>"{}|\\^\[\]`]+)',
        # URLs with www but no protocol
        r'(www\.[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"{}|\\^\[\]`]*)',
        # FTP URLs
        r'(ftp://[^\s<>"{}|\\^\[\]`]+)',
        # URLs in angle brackets or parentheses
        r"[<\(](https?://[^>\)]+)[>\)]",
        # Markdown style links
        r"\[([^\]]+)\]\((https?://[^\)]+)\)",
        # URLs with common domains even without www
        r'([a-zA-Z0-9][a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|mil|int|co\.uk|ac\.uk|io|ai|app|dev|tech|online|store|shop|site|website|web|info|biz|name|pro|xyz|top|club|vip|ltd|group|email|fund|cash|gold|plus|world|today|life|live|love|care|one|mobi|asia|eu|us|uk|ca|de|fr|au|in|ru|ch|jp|cn|br|it|nl|se|no|es|mil)[/\s<>"\'.,;:!?\)]*)',
        # Email style links that might be URLs
        r"<(https?://[^>]+)>",
    ]

    # Process href matches
    for link in href_matches:
        link = link.strip()
        # Handle relative URLs by checking if they look like full URLs
        if link.startswith(("http://", "https://", "ftp://", "www.")):
            if link.startswith("www."):
                link = "http://" + link
            if link not in seen_links:
                links.append(link)
                seen_links.add(link)

    # Find all URLs in content
    for pattern in url_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            # Handle tuples from grouped patterns
            if isinstance(match, tuple):
                for m in match:
                    if m and m.startswith(("http://", "https://", "ftp://")):
                        if m not in seen_links:
                            links.append(m)
                            seen_links.add(m)
            else:
                url = match.strip()
                # Add protocol if missing
                if url.startswith("www."):
                    url = "http://" + url
                elif not url.startswith(("http://", "https://", "ftp://")) and re.match(
                    r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", url
                ):
                    url = "http://" + url

                # Validate and clean URL
                if url.startswith(("http://", "https://", "ftp://")):
                    # Remove trailing punctuation and HTML artifacts
                    url = re.sub(r'[.,;:!?\'">\)<\]/]+$', "", url)
                    # Remove common email endings that might be caught
                    url = re.sub(r"[\s]*\[[^\]]+\]$", "", url)
                    # Remove any trailing HTML tags
                    url = re.sub(r"<[^>]*$", "", url)

                    if url not in seen_links and len(url) > 10:  # Minimum URL length
                        links.append(url)
                        seen_links.add(url)

    return list(links)


def extract_domains_from_links(links):
    """Extract unique domains from links"""
    domains = set()

    for link in links:
        try:
            # Extract just the domain name without protocol
            if link.startswith(("http://", "https://", "ftp://")):
                # Extract domain without protocol
                domain_match = re.match(r"https?://([^/\s?#]+)", link)
                if not domain_match:
                    domain_match = re.match(r"ftp://([^/\s?#]+)", link)

                if domain_match:
                    domain = domain_match.group(1)
                    # Remove www. prefix for cleaner domain
                    clean_domain = domain.replace("www.", "")
                    # Remove port number if present (e.g., example.com:8080)
                    clean_domain = re.sub(r":\d+$", "", clean_domain)
                    domains.add(clean_domain)
        except:
            continue

    return list(domains)


def parse_eml_to_json(eml_path, tenant_id="2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a"):
    """Parse EML file and convert to required JSON format"""
    # Try to parse with default policy first, then fallback to compat32
    try:
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except:
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.compat32)

    # Extract basic information
    subject = msg.get("Subject", "")
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    cc_header = msg.get("Cc", "")
    bcc_header = msg.get("Bcc", "")
    reply_to_header = msg.get("Reply-To", "")
    message_id = msg.get("Message-ID", f"<{uuid.uuid4()}@generated>")

    # Extract and validate sender email
    sender_email = validate_and_fix_email(from_header)

    # If sender email extraction failed, try alternative headers
    if not sender_email:
        # Try Sender header
        sender_header = msg.get("Sender", "")
        if sender_header:
            sender_email = validate_and_fix_email(sender_header)

        # If still no sender, try Reply-To as fallback
        if not sender_email and reply_to_header:
            sender_email = validate_and_fix_email(reply_to_header)

        # If still no sender, generate a random unique email
        if not sender_email:
            sender_email = generate_random_email()

    # Extract return path, use sender email if not available
    return_path = msg.get("Return-Path", "")
    if return_path:
        return_path = validate_and_fix_email(return_path)
        # If return path validation failed, use sender
        if not return_path:
            return_path = sender_email
    else:
        return_path = sender_email

    # Extract recipients
    to_recipients = extract_email_addresses(to_header)
    cc_recipients = extract_email_addresses(cc_header)
    bcc_recipients = extract_email_addresses(bcc_header)
    reply_to_recipients = extract_email_addresses(reply_to_header)

    # If no TO recipients found, generate a random one
    if not to_recipients:
        random_recipient = generate_random_email()
        to_recipients = [{"emailAddress": {"name": "", "address": random_recipient}}]

    # Use fixed mailbox_id for all files
    mailbox_id = "atharv@hackntrain.com"

    # Extract dates
    date_header = msg.get("Date", "")
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
            if part.get_content_type() == "text/html":
                try:
                    body_content = part.get_content()
                except:
                    body_content = part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                content_type = "html"
                break
            elif part.get_content_type() == "text/plain" and not body_content:
                try:
                    body_content = part.get_content()
                except:
                    body_content = part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                content_type = "text"
    else:
        try:
            body_content = msg.get_content()
        except:
            body_content = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        if msg.get_content_type() == "text/html":
            content_type = "html"

    # Extract links and domains from any content (HTML or text)
    links = []
    domains = []
    plain_text_content = body_content

    # Always extract links, regardless of content type
    links = extract_links_from_content(body_content)
    domains = extract_domains_from_links(links)

    # Extract plain text if HTML
    if content_type == "html":
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
            if (
                content_disposition == "attachment"
                or (
                    content_disposition == "inline"
                    and not content_type.startswith("text/")
                )
                or (content_type.startswith("image/") and part.get_filename())
            ):
                has_attachments = True

                # Get attachment details
                filename = part.get_filename()
                if filename:
                    # Get content type
                    content_type = part.get_content_type()

                    # Get attachment content as base64
                    try:
                        # Get transfer encoding
                        transfer_encoding = part.get(
                            "Content-Transfer-Encoding", ""
                        ).lower()

                        if transfer_encoding == "base64":
                            # Content is already base64 encoded
                            content = part.get_payload()
                            # Remove any whitespace/newlines
                            if isinstance(content, str):
                                content = (
                                    content.replace("\n", "").replace("\r", "").strip()
                                )
                        else:
                            # Decode and re-encode as base64
                            raw_content = part.get_payload(decode=True)
                            if raw_content:
                                content = base64.b64encode(raw_content).decode("utf-8")
                            else:
                                content = ""
                    except Exception as e:
                        # Fallback: try to get content as is
                        try:
                            content = part.get_payload()
                            if not isinstance(content, str):
                                content = base64.b64encode(content).decode("utf-8")
                        except:
                            content = ""

                    attachments.append(
                        {
                            "name": filename,
                            "contentBytes": content,
                            "contentType": content_type,
                        }
                    )

    # Extract SPF, DKIM, DMARC from headers (if available)
    auth_results = msg.get("Authentication-Results", "")
    spf_result = None
    dkim_result = None
    dmarc_result = None

    if auth_results:
        # Check for SPF
        if "spf=pass" in auth_results:
            spf_result = "pass"
        elif "spf=fail" in auth_results:
            spf_result = "fail"
        elif "spf=neutral" in auth_results:
            spf_result = "neutral"
        elif "spf=none" in auth_results:
            spf_result = "none"

        # Check for DKIM
        if "dkim=pass" in auth_results:
            dkim_result = "pass"
        elif "dkim=fail" in auth_results:
            dkim_result = "fail"
        elif "dkim=neutral" in auth_results:
            dkim_result = "neutral"
        elif "dkim=none" in auth_results:
            dkim_result = "none"

        # Check for DMARC
        if "dmarc=pass" in auth_results:
            dmarc_result = "pass"
        elif "dmarc=fail" in auth_results:
            dmarc_result = "fail"
        elif "dmarc=none" in auth_results:
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
    received_headers = msg.get_all("Received", [])
    for received in received_headers:
        # Look for IP addresses in brackets
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", received)
        if not ip_match:
            # Look for IPv6 addresses
            ip_match = re.search(r"\[([0-9a-fA-F:]+)\]", received)
        if ip_match:
            ip_address = ip_match.group(1)
            break

    # Use random IP if not found
    if not ip_address:
        ip_address = random.choice(IP_ADDRESSES)

    # Create unique message ID with test-malicious format
    filename_without_ext = os.path.splitext(os.path.basename(eml_path))[0]
    unique_id = f"test-spam-{filename_without_ext}"

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
                "sender": {"emailAddress": {"name": "", "address": sender_email}},
                "from": {"emailAddress": {"name": "", "address": sender_email}},
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients,
                "bccRecipients": bcc_recipients,
                "replyTo": reply_to_recipients,
                "receivedDateTime": date_str,
                "sentDateTime": date_str,
                "body": {"contentType": content_type, "content": body_content},
                "hasAttachments": has_attachments,
                "internetMessageId": message_id,
                "importance": "normal",
                "isRead": False,
                "isDraft": False,
                "flag": {"flagStatus": "notFlagged"},
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
                "list_unsubscribe_one_click": False,
            },
            "payload": {
                "content": (
                    plain_text_content[:500] if plain_text_content else ""
                ),  # First 500 chars
                "links": links,
                "domains": domains,
            },
        },
    }

    # Add attachments to the JSON if present
    if attachments:
        json_data["email_data"]["attachments"] = attachments

    return json_data


def main():
    """Main function to process all EML files"""
    # Get the folder path from user or use current directory
    folder_path = input(
        "Enter the folder path containing EML files (press Enter for current directory): "
    ).strip()
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
    eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith(".eml")]

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
            json_filename = json_data["message_id"] + ".json"
            json_path = os.path.join(output_dir, json_filename)

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)

            successful += 1

            # Check if file has attachments
            if "attachments" in json_data.get("email_data", {}):
                files_with_attachments.append((eml_file, json_filename))
                print(
                    f"  ✓ Converted successfully: {json_filename} (Has {len(json_data['email_data']['attachments'])} attachment(s))"
                )
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
