#!/usr/bin/env python3
"""
EML Duplicate Content Detector
This tool finds EML files with duplicate content and moves them to a separate folder.
"""

import os
import sys
import email
from email import policy
import hashlib
import re
import shutil
from datetime import datetime
from collections import defaultdict
import html

class EMLDuplicateDetector:
    def __init__(self):
        self.content_signatures = defaultdict(list)  # signature -> [file_paths]
        self.unique_files = []
        self.duplicate_files = []
        self.total_files = 0
        self.duplicate_folder = "duplicate_emails"
        
    def extract_email_content(self, eml_path):
        """Extract normalized content from email for comparison"""
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # 1. Extract and clean subject
            subject = msg.get('Subject', '').strip()
            # Remove RE:, FW:, FWD: prefixes
            clean_subject = re.sub(r'^(re:|fw:|fwd:|re\[\d+\]:|fw\[\d+\]:)\s*', '', subject, flags=re.I)
            clean_subject = clean_subject.strip().lower()
            
            # 2. Extract body content
            body_content = ""
            html_content = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    
                    # Skip attachments
                    if "attachment" in content_disposition:
                        continue
                        
                    try:
                        if content_type == 'text/plain':
                            body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        elif content_type == 'text/html':
                            html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        continue
            else:
                # Single part message
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='ignore')
                        if msg.get_content_type() == 'text/html':
                            html_content = content
                        else:
                            body_content = content
                except:
                    pass
            
            # Use plain text if available, otherwise strip HTML
            if body_content:
                final_content = body_content
            elif html_content:
                # Strip HTML tags
                final_content = re.sub(r'<[^>]+>', '', html_content)
                final_content = html.unescape(final_content)
            else:
                final_content = ""
            
            # 3. Normalize content
            # Remove extra whitespace, newlines, etc.
            final_content = re.sub(r'\s+', ' ', final_content).strip().lower()
            # Remove common signatures/footers
            final_content = re.sub(r'(unsubscribe|click here to unsubscribe|to stop receiving).*$', '', final_content, flags=re.I)
            # Remove URLs to focus on text content
            final_content = re.sub(r'https?://[^\s]+', '[URL]', final_content)
            final_content = re.sub(r'www\.[^\s]+', '[URL]', final_content)
            # Remove email addresses
            final_content = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', final_content)
            
            # 4. Extract attachment info
            attachment_info = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_disposition() == 'attachment':
                        filename = part.get_filename()
                        if filename:
                            # Get size and type
                            content = part.get_payload(decode=True)
                            if content:
                                size = len(content)
                                # Create a hash of attachment content
                                att_hash = hashlib.md5(content).hexdigest()
                                attachment_info.append(f"{filename}|{size}|{att_hash}")
            
            # 5. Create content signature
            content_parts = [clean_subject, final_content]
            if attachment_info:
                content_parts.extend(sorted(attachment_info))
            
            content_signature = "|".join(content_parts)
            
            # 6. Generate hash
            content_hash = hashlib.sha256(content_signature.encode()).hexdigest()
            
            return content_hash, {
                'subject': clean_subject,
                'content_preview': final_content[:100] + '...' if len(final_content) > 100 else final_content,
                'has_attachments': len(attachment_info) > 0,
                'attachment_count': len(attachment_info)
            }
            
        except Exception as e:
            print(f"  ⚠️  Error processing {eml_path}: {str(e)}")
            return None, None
    
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
        
        print(f"\nFound {self.total_files} EML files to analyze...")
        print("=" * 70)
        
        # First pass: Generate content signatures
        print("\nPhase 1: Analyzing email content...")
        for eml_path in sorted(eml_files):
            filename = os.path.basename(eml_path)
            print(f"Analyzing: {filename}", end=' ')
            
            content_hash, content_info = self.extract_email_content(eml_path)
            
            if content_hash:
                self.content_signatures[content_hash].append({
                    'path': eml_path,
                    'filename': filename,
                    'info': content_info
                })
                print("✓")
            else:
                print("✗ (skipped)")
        
        # Second pass: Identify duplicates
        print(f"\nPhase 2: Identifying duplicates...")
        duplicate_groups = []
        
        for content_hash, file_list in self.content_signatures.items():
            if len(file_list) > 1:
                # Found duplicates
                duplicate_groups.append(file_list)
                # Keep the first file, mark others as duplicates
                self.unique_files.append(file_list[0]['path'])
                for dup in file_list[1:]:
                    self.duplicate_files.append(dup['path'])
            else:
                # Unique file
                self.unique_files.append(file_list[0]['path'])
        
        # Report findings
        print(f"\nFound {len(duplicate_groups)} groups of duplicate content")
        print(f"Total duplicate files to move: {len(self.duplicate_files)}")
        
        if duplicate_groups:
            print("\nDuplicate groups found:")
            for i, group in enumerate(duplicate_groups, 1):
                print(f"\nGroup {i} ({len(group)} files with same content):")
                print(f"  Subject: {group[0]['info']['subject']}")
                print(f"  Content preview: {group[0]['info']['content_preview']}")
                print(f"  Files:")
                for file_info in group:
                    status = "📌 KEPT" if file_info['path'] in self.unique_files else "📋 DUPLICATE"
                    print(f"    {status} {file_info['filename']}")
        
        # Move duplicates if found
        if self.duplicate_files:
            self._move_duplicates(folder_path)
        else:
            print("\n✅ No duplicate content found! All emails are unique.")
        
        # Print summary
        self._print_summary()
    
    def _move_duplicates(self, folder_path):
        """Move duplicate files to a separate folder"""
        duplicate_folder_path = os.path.join(folder_path, self.duplicate_folder)
        
        # Create duplicate folder
        try:
            os.makedirs(duplicate_folder_path, exist_ok=True)
            print(f"\n📁 Created/Using duplicate folder: {self.duplicate_folder}")
        except Exception as e:
            print(f"\n❌ Error creating duplicate folder: {str(e)}")
            return
        
        # Move duplicate files
        print("\nMoving duplicate files...")
        moved_count = 0
        
        for dup_path in self.duplicate_files:
            filename = os.path.basename(dup_path)
            dest_path = os.path.join(duplicate_folder_path, filename)
            
            try:
                # Handle filename conflicts
                if os.path.exists(dest_path):
                    base, ext = os.path.splitext(filename)
                    counter = 1
                    while os.path.exists(dest_path):
                        new_filename = f"{base}_{counter}{ext}"
                        dest_path = os.path.join(duplicate_folder_path, new_filename)
                        counter += 1
                
                # Move the file
                shutil.move(dup_path, dest_path)
                print(f"  ✓ Moved: {filename}")
                moved_count += 1
                
            except PermissionError:
                print(f"  ⚠️  Permission denied: {filename}")
            except Exception as e:
                print(f"  ❌ Error moving {filename}: {str(e)}")
        
        print(f"\nSuccessfully moved {moved_count} duplicate files")
    
    def _print_summary(self):
        """Print processing summary"""
        print("\n" + "=" * 70)
        print("PROCESSING SUMMARY")
        print("=" * 70)
        print(f"Total files analyzed: {self.total_files}")
        print(f"Unique content files: {len(self.unique_files)} ({len(self.unique_files)/self.total_files*100:.1f}%)")
        print(f"Duplicate content files: {len(self.duplicate_files)} ({len(self.duplicate_files)/self.total_files*100:.1f}%)")
        
        if self.duplicate_files:
            print(f"\n📁 Duplicate files have been moved to: ./{self.duplicate_folder}/")
            print("📌 Original folder now contains only unique content emails")

def main():
    """Main function"""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║          EML Duplicate Content Detector & Mover              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\nThis tool will:")
    print("1. Analyze email content (subject + body + attachments)")
    print("2. Identify emails with duplicate content")
    print("3. Keep one copy of each unique content")
    print("4. Move duplicates to a 'duplicate_emails' folder\n")
    
    # Get folder path from user
    if len(sys.argv) > 1:
        folder_path = sys.argv[1]
    else:
        folder_path = input("Enter the folder path containing EML files: ").strip()
    
    if not folder_path:
        print("Error: No folder path provided!")
        return
    
    # Confirm with user
    print(f"\n📍 Will analyze EML files in: {os.path.abspath(folder_path)}")
    print("📋 Duplicates will be moved to: duplicate_emails/")
    
    confirm = input("\nProceed? (yes/no): ").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print("Operation cancelled.")
        return
    
    # Process the folder
    detector = EMLDuplicateDetector()
    detector.process_folder(folder_path)

if __name__ == "__main__":
    main()