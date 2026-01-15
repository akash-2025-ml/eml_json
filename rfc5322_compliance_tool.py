#!/usr/bin/env python3
"""
RFC 5322 Email Compliance Checker and Cleaner
This tool checks EML files for RFC 5322 compliance and removes non-compliant files.
"""

import os
import sys
import email
from email import policy
from email.utils import parsedate_to_datetime
import re
from datetime import datetime
import shutil

class RFC5322ComplianceChecker:
    def __init__(self):
        self.deleted_files = []
        self.compliant_files = []
        self.permission_errors = []
        self.total_files = 0
        
    def check_rfc5322_compliance(self, eml_path):
        """
        Check if an EML file follows RFC 5322 standards.
        Returns (is_compliant, issues_list)
        """
        issues = []
        
        try:
            # Parse the email
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # 1. Check required From header (RFC 5322 Section 3.6.2)
            from_header = msg.get('From')
            if not from_header:
                issues.append("Missing required 'From' header")
            else:
                # Validate From email format
                if not self._validate_email_header(from_header):
                    issues.append(f"Invalid From email format: {from_header}")
            
            # 2. Check required Date header (RFC 5322 Section 3.6.1)
            date_header = msg.get('Date')
            if not date_header:
                issues.append("Missing required 'Date' header")
            else:
                # Validate date format
                try:
                    parsedate_to_datetime(date_header)
                except Exception as e:
                    issues.append(f"Invalid date format: {date_header}")
            
            # 3. Check Message-ID format if present (RFC 5322 Section 3.6.4)
            message_id = msg.get('Message-ID')
            if message_id and not self._validate_message_id(message_id):
                issues.append(f"Invalid Message-ID format: {message_id}")
            
            # 4. Check header/body structure
            if not self._check_header_body_structure(eml_path):
                issues.append("No blank line separating headers from body")
            
            # 5. Check line length (RFC 5322 Section 2.1.1)
            if not self._check_line_length(eml_path):
                issues.append("Lines exceed 998 characters limit")
            
            # 6. Check To/Cc/Bcc email formats if present
            for header in ['To', 'Cc', 'Bcc']:
                value = msg.get(header)
                if value and not self._validate_email_header(value):
                    issues.append(f"Invalid {header} email format: {value}")
            
            # 7. Check Reply-To format if present
            reply_to = msg.get('Reply-To')
            if reply_to and not self._validate_email_header(reply_to):
                issues.append(f"Invalid Reply-To email format: {reply_to}")
            
            # 8. For multipart messages, check MIME-Version
            if msg.is_multipart() and not msg.get('MIME-Version'):
                issues.append("Multipart message missing MIME-Version header")
                
        except Exception as e:
            issues.append(f"Failed to parse email file: {str(e)}")
        
        is_compliant = len(issues) == 0
        return is_compliant, issues
    
    def _validate_email_header(self, header_value):
        """Validate email address format in header"""
        if not header_value:
            return False
        
        # Basic patterns for email validation
        # Pattern 1: Simple email
        simple_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        # Pattern 2: Email with display name
        with_name = r'^[^<>]*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$'
        # Pattern 3: Multiple emails
        
        # Remove extra whitespace
        header_value = ' '.join(header_value.split())
        
        # Check for multiple addresses
        if ',' in header_value:
            # Split and validate each
            addresses = header_value.split(',')
            for addr in addresses:
                addr = addr.strip()
                if not (re.match(simple_email, addr) or re.match(with_name, addr)):
                    return False
            return True
        else:
            # Single address
            return bool(re.match(simple_email, header_value) or re.match(with_name, header_value))
    
    def _validate_message_id(self, message_id):
        """Validate Message-ID format"""
        # RFC 5322: Message-ID should be <id-left@id-right>
        return bool(re.match(r'^<[^@\s]+@[^@\s]+>$', message_id))
    
    def _check_header_body_structure(self, eml_path):
        """Check if headers are properly separated from body"""
        with open(eml_path, 'rb') as f:
            content = f.read()
        return b'\r\n\r\n' in content or b'\n\n' in content
    
    def _check_line_length(self, eml_path):
        """Check if any line exceeds 998 characters"""
        with open(eml_path, 'rb') as f:
            for line in f:
                if len(line.rstrip(b'\r\n')) > 998:
                    return False
        return True
    
    def process_folder(self, folder_path):
        """Process all EML files in the folder"""
        if not os.path.exists(folder_path):
            print(f"Error: Folder '{folder_path}' does not exist!")
            return
        
        # Find all EML files
        eml_files = []
        for file in os.listdir(folder_path):
            if file.lower().endswith('.eml'):
                eml_files.append(os.path.join(folder_path, file))
        
        self.total_files = len(eml_files)
        
        if self.total_files == 0:
            print("No EML files found in the specified folder.")
            return
        
        print(f"\nFound {self.total_files} EML files to check...")
        print("=" * 70)
        
        # Create backup folder
        backup_folder = os.path.join(folder_path, 'non_compliant_backup')
        
        # Process each file
        for eml_path in sorted(eml_files):
            filename = os.path.basename(eml_path)
            print(f"\nChecking: {filename}")
            
            is_compliant, issues = self.check_rfc5322_compliance(eml_path)
            
            if is_compliant:
                print(f"  ✅ COMPLIANT - File meets RFC 5322 standards")
                self.compliant_files.append(filename)
            else:
                print(f"  ❌ NON-COMPLIANT - Found {len(issues)} issue(s):")
                for issue in issues:
                    print(f"     - {issue}")
                
                # Create backup folder if needed
                if not os.path.exists(backup_folder):
                    os.makedirs(backup_folder)
                    print(f"\n  📁 Created backup folder: {backup_folder}")
                
                # Backup the file before deletion
                backup_path = os.path.join(backup_folder, filename)
                try:
                    shutil.copy2(eml_path, backup_path)
                    print(f"  💾 Backed up to: {backup_path}")
                    
                    # Delete the non-compliant file
                    try:
                        os.remove(eml_path)
                        print(f"  🗑️  DELETED: {filename}")
                        self.deleted_files.append(filename)
                    except PermissionError:
                        print(f"  ⚠️  PERMISSION DENIED: Could not delete {filename}")
                        print(f"     File is in use or requires admin privileges")
                        print(f"     File backed up but original kept")
                        self.permission_errors.append(filename)
                    except Exception as e:
                        print(f"  ⚠️  ERROR deleting file: {str(e)}")
                        
                except PermissionError:
                    print(f"  ⚠️  PERMISSION DENIED: Could not backup {filename}")
                    print(f"     File is in use or requires admin privileges")
                    print(f"     Skipping this file")
                    self.permission_errors.append(filename)
                except Exception as e:
                    print(f"  ⚠️  ERROR backing up file: {str(e)}")
                    print(f"     Skipping this file")
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print processing summary"""
        print("\n" + "=" * 70)
        print("PROCESSING SUMMARY")
        print("=" * 70)
        print(f"Total files processed: {self.total_files}")
        print(f"Compliant files (kept): {len(self.compliant_files)} ({len(self.compliant_files)/self.total_files*100:.1f}%)")
        print(f"Non-compliant files (deleted): {len(self.deleted_files)} ({len(self.deleted_files)/self.total_files*100:.1f}%)")
        if self.permission_errors:
            print(f"Permission errors: {len(self.permission_errors)} ({len(self.permission_errors)/self.total_files*100:.1f}%)")
        
        if self.compliant_files:
            print("\n✅ Compliant files (kept):")
            for f in sorted(self.compliant_files):
                print(f"   - {f}")
        
        if self.deleted_files:
            print("\n❌ Non-compliant files (deleted):")
            for f in sorted(self.deleted_files):
                print(f"   - {f}")
            print(f"\n💡 Deleted files were backed up to the 'non_compliant_backup' folder")
        
        if self.permission_errors:
            print("\n⚠️  Files with permission errors (not deleted):")
            for f in sorted(self.permission_errors):
                print(f"   - {f}")
            print(f"\n💡 Try running as administrator or closing programs using these files")

def main():
    """Main function"""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        RFC 5322 Email Compliance Checker & Cleaner           ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\nThis tool will:")
    print("1. Check all EML files for RFC 5322 compliance")
    print("2. Delete non-compliant files (with backup)")
    print("3. Keep only compliant files in the folder\n")
    
    # Get folder path from user
    if len(sys.argv) > 1:
        folder_path = sys.argv[1]
    else:
        folder_path = input("Enter the folder path containing EML files: ").strip()
    
    if not folder_path:
        print("Error: No folder path provided!")
        return
    
    # Confirm with user
    print(f"\n⚠️  WARNING: Non-compliant files will be DELETED from:")
    print(f"   {os.path.abspath(folder_path)}")
    print("\n   (Files will be backed up before deletion)")
    
    confirm = input("\nDo you want to proceed? (yes/no): ").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print("Operation cancelled.")
        return
    
    # Process the folder
    checker = RFC5322ComplianceChecker()
    checker.process_folder(folder_path)

if __name__ == "__main__":
    main()