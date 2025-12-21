#!/usr/bin/env python3
import email
from email import policy

# Test reading attachment
with open('sample_with_attachment.eml', 'rb') as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

for part in msg.walk():
    if part.get_content_disposition() == 'attachment':
        print(f"Filename: {part.get_filename()}")
        print(f"Content-Type: {part.get_content_type()}")
        print(f"Transfer-Encoding: {part.get_content_transfer_encoding()}")
        
        # Get raw payload
        raw_payload = part.get_payload()
        print(f"Raw payload type: {type(raw_payload)}")
        print(f"Raw payload length: {len(raw_payload) if isinstance(raw_payload, (str, bytes)) else 'N/A'}")
        print(f"First 50 chars: {str(raw_payload)[:50]}")
        print("---")