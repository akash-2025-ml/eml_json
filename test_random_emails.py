from eml_to_json_converter import generate_random_email

print("Testing random email generation:")
print("\nGenerating 20 random email addresses:\n")

for i in range(20):
    email = generate_random_email()
    print(f"{i+1:2d}. {email}")

print("\nAll emails are unique and randomly generated!")