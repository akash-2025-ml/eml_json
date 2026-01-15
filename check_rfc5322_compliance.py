#!/usr/bin/env python3
import os
import email
from email import policy
from email.utils import parsedate_to_datetime
import re
from datetime import datetime

def check_rfc5322_compliance(eml_path):
    """Check if an EML file follows RFC 5322 standards"""
    compliance_issues = []
    compliance_checks = {
        'required_headers': {'From': False, 'Date': False},
        'date_format': False,
        'message_id_format': False,
        'email_format': False,
        'header_structure': False,
        'mime_structure': False
    }
    
    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        
        # Check required headers (RFC 5322: From and Date are required)
        if msg.get('From'):
            compliance_checks['required_headers']['From'] = True
        else:
            compliance_issues.append("Missing required 'From' header")
            
        if msg.get('Date'):
            compliance_checks['required_headers']['Date'] = True
            # Check date format
            try:
                date_header = msg.get('Date')
                parsed_date = parsedate_to_datetime(date_header)
                compliance_checks['date_format'] = True
            except:
                compliance_issues.append(f"Invalid date format: {date_header}")
        else:
            compliance_issues.append("Missing required 'Date' header")
        
        # Check Message-ID format if present
        message_id = msg.get('Message-ID')
        if message_id:
            # RFC 5322: Message-ID should be <id-left@id-right>
            if re.match(r'^<[^@\s]+@[^@\s]+>$', message_id):
                compliance_checks['message_id_format'] = True
            else:
                compliance_issues.append(f"Invalid Message-ID format: {message_id}")
        
        # Check email address formats
        email_pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
        from_header = msg.get('From', '')
        
        # Extract email from From header
        from_match = re.search(r'<([^>]+)>', from_header)
        if from_match:
            from_email = from_match.group(1)
        else:
            from_email = from_header.strip()
        
        if from_email and re.match(email_pattern, from_email):
            compliance_checks['email_format'] = True
        elif from_email:
            compliance_issues.append(f"Invalid From email format: {from_header}")
        
        # Check header structure (should have headers before body)
        raw_email = open(eml_path, 'rb').read()
        if b'\r\n\r\n' in raw_email or b'\n\n' in raw_email:
            compliance_checks['header_structure'] = True
        else:
            compliance_issues.append("No blank line separating headers from body")
        
        # Check MIME structure if multipart
        if msg.is_multipart():
            content_type = msg.get_content_type()
            if msg.get('MIME-Version'):
                compliance_checks['mime_structure'] = True
            else:
                compliance_issues.append("Multipart message missing MIME-Version header")
                
        # Additional checks
        # Check for extremely long lines (RFC 5322: lines should be <998 chars)
        lines = raw_email.decode('utf-8', errors='ignore').split('\n')
        for i, line in enumerate(lines):
            if len(line) > 998:
                compliance_issues.append(f"Line {i+1} exceeds 998 characters")
                break
        
        # Check To/Cc/Bcc format if present
        for header in ['To', 'Cc', 'Bcc']:
            value = msg.get(header)
            if value and '@' in value:
                # Basic check for email format
                if not re.search(r'[^@\s]+@[^@\s]+', value):
                    compliance_issues.append(f"Invalid {header} format: {value}")
        
    except Exception as e:
        compliance_issues.append(f"Failed to parse email: {str(e)}")
    
    return compliance_checks, compliance_issues

def main():
    """Check all EML files in the directory"""
    eml_files = [f for f in os.listdir('.') if f.lower().endswith('.eml')]
    
    print(f"Checking {len(eml_files)} EML files for RFC 5322 compliance...\n")
    print("=" * 80)
    
    compliant_files = []
    non_compliant_files = []
    
    for eml_file in sorted(eml_files):
        print(f"\nChecking: {eml_file}")
        print("-" * 40)
        
        checks, issues = check_rfc5322_compliance(eml_file)
        
        # Count passed checks
        passed = sum(1 for k, v in checks.items() 
                    if k != 'required_headers' and v == True)
        passed += sum(1 for v in checks['required_headers'].values() if v == True)
        total = 6  # Total number of checks
        
        print(f"Compliance: {passed}/{total} checks passed")
        
        # Show check results
        print("  ✓ From header" if checks['required_headers']['From'] else "  ✗ From header")
        print("  ✓ Date header" if checks['required_headers']['Date'] else "  ✗ Date header")
        print("  ✓ Date format" if checks['date_format'] else "  ✗ Date format")
        print("  ✓ Message-ID format" if checks['message_id_format'] else "  ✗ Message-ID format")
        print("  ✓ Email format" if checks['email_format'] else "  ✗ Email format")
        print("  ✓ MIME structure" if checks['mime_structure'] else "  ✗ MIME structure")
        
        if issues:
            print("\nIssues found:")
            for issue in issues:
                print(f"  - {issue}")
            non_compliant_files.append((eml_file, len(issues)))
        else:
            print("\n  ✅ Fully RFC 5322 compliant!")
            compliant_files.append(eml_file)
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total files checked: {len(eml_files)}")
    print(f"Fully compliant: {len(compliant_files)}")
    print(f"Non-compliant: {len(non_compliant_files)}")
    
    if compliant_files:
        print("\nFully compliant files:")
        for f in compliant_files:
            print(f"  ✅ {f}")
    
    if non_compliant_files:
        print("\nNon-compliant files:")
        for f, issue_count in sorted(non_compliant_files, key=lambda x: x[1], reverse=True):
            print(f"  ⚠️  {f} ({issue_count} issues)")
    
    # Compare with samples
    print("\n" + "=" * 80)
    print("COMPARISON WITH RFC 5322 SAMPLE FORMATS")
    print("=" * 80)
    
    sample_features = {
        "Basic headers (From, To, Subject, Date)": 0,
        "Multiple recipients (To, Cc, Bcc)": 0,
        "Threading headers (In-Reply-To, References)": 0,
        "MIME multipart structure": 0,
        "Authentication headers (SPF, DKIM, DMARC)": 0,
        "Extended headers (X-headers, List-headers)": 0,
        "Proper email display names": 0,
        "Return-Path header": 0,
        "Received headers (routing)": 0,
        "Content-Transfer-Encoding": 0
    }
    
    for eml_file in eml_files:
        try:
            with open(eml_file, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # Check which features are present
            if all(msg.get(h) for h in ['From', 'To', 'Subject', 'Date']):
                sample_features["Basic headers (From, To, Subject, Date)"] += 1
            
            if msg.get('Cc') or msg.get('Bcc') or ',' in str(msg.get('To', '')):
                sample_features["Multiple recipients (To, Cc, Bcc)"] += 1
            
            if msg.get('In-Reply-To') or msg.get('References'):
                sample_features["Threading headers (In-Reply-To, References)"] += 1
            
            if msg.is_multipart():
                sample_features["MIME multipart structure"] += 1
            
            auth_results = msg.get('Authentication-Results', '')
            if 'spf=' in auth_results or 'dkim=' in auth_results or 'dmarc=' in auth_results:
                sample_features["Authentication headers (SPF, DKIM, DMARC)"] += 1
            
            # Check for X-headers or List headers
            x_headers = [h for h in msg.keys() if h.startswith('X-') or h.startswith('List-')]
            if x_headers:
                sample_features["Extended headers (X-headers, List-headers)"] += 1
            
            # Check for display names
            from_header = msg.get('From', '')
            if '<' in from_header and '>' in from_header and from_header.index('<') > 1:
                sample_features["Proper email display names"] += 1
            
            if msg.get('Return-Path'):
                sample_features["Return-Path header"] += 1
            
            if msg.get_all('Received'):
                sample_features["Received headers (routing)"] += 1
            
            if any(part.get('Content-Transfer-Encoding') for part in msg.walk()):
                sample_features["Content-Transfer-Encoding"] += 1
                
        except:
            pass
    
    print("\nFeature usage across all EML files:")
    for feature, count in sorted(sample_features.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(eml_files)) * 100 if eml_files else 0
        print(f"  {feature}: {count}/{len(eml_files)} ({percentage:.1f}%)")

if __name__ == "__main__":
    main()