# python -m streamlit run c:/project/bca.py
# 

# import PyPDF2
# import streamlit as st
# import re
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from datetime import datetime

# def extract_pdf_info(file):
#     reader = PyPDF2.PdfReader(file)
#     text = ''
#     for page in reader.pages:
#         text += page.extract_text() or ''
#     # Clean up extra spaces in the text
#     text = re.sub(r'\s+', ' ', text)
#     return text

# def extract_info(certificate_data):
#     # Debug: Show cleaned certificate data
#     st.write("Cleaned Certificate Text:", certificate_data)
    
#     # Modified patterns for Coursera certificates
#     # Pattern for dates like "May 2, 2024"
#     issue_date = re.search(r'([A-Z][a-z]+)\s+(\d{1,2})\s*,\s*(\d{4})', certificate_data)
    
#     # Pattern for name (assuming it's in all caps)
#     name = re.search(r'([A-Z\s]+)(?=\s*[A-Za-z\s]+has successfully completed|Su pervised)', certificate_data)
    
#     # Pattern for course name
#     course_name = re.search(r'([\w\s:]+)(?=an online non-credit course)', certificate_data)
    
#     # Pattern for issuer (DeepLearning.AI and Stanford University)
#     issuer_name = re.search(r'authorized by ([\w\s.,]+) and offered through Coursera', certificate_data)
    
#     # Debug information
#     if issue_date:
#         month, day, year = issue_date.groups()
#         date_str = f"{month} {day}, {year}"
#         st.write("Found Issue Date:", date_str)
#     else:
#         st.write("Issue Date not found")
        
#     if name:
#         st.write("Found Name:", name.group(1).strip())
    
#     if course_name:
#         st.write("Found Course:", course_name.group(1).strip())
        
#     if issuer_name:
#         st.write("Found Issuer:", issuer_name.group(1).strip())

#     try:
#         if issue_date:
#             # Convert the date string to datetime
#             month, day, year = issue_date.groups()
#             issue_date = datetime.strptime(f"{month} {day} {year}", '%B %d %Y')
#             # Set expiry date to 100 years from issue date (lifetime certificate)
#             expiry_date = datetime(issue_date.year + 100, issue_date.month, issue_date.day)
#             issuer = issuer_name.group(1).strip() if issuer_name else "DeepLearning.AI and Stanford University"
#             return issue_date, expiry_date, issuer
#     except Exception as e:
#         st.error(f"Error processing dates: {str(e)}")
    
#     return None, None, None

# def verify_signature(public_key_pem, signature, certificate_data):
#     # For Coursera certificates, we can verify using the verification URL
#     verification_url = re.search(r'https://coursera.org/verify/([A-Z0-9]+)', certificate_data)
#     if verification_url:
#         st.write("Verification URL found:", verification_url.group(0))
#         return True
#     return False

# def check_issuer(issuer_name):
#     trusted_issuers = ["DeepLearning.AI and Stanford University", "Coursera"]
#     return any(trusted_issuer in issuer_name for trusted_issuer in trusted_issuers)

# def check_expiration(issue_date, expiry_date):
#     current_date = datetime.now()
#     return current_date < expiry_date

# # Initialize session state for history
# if 'history' not in st.session_state:
#     st.session_state.history = []

# # Streamlit app
# st.title('Coursera Certificate Verifier')

# # File uploader
# uploaded_file = st.file_uploader("Upload your Coursera certificate", type="pdf", key="file_uploader_1")

# if uploaded_file is not None:
#     try:
#         certificate_data = extract_pdf_info(uploaded_file)
        
#         # Extract information
#         issue_date, expiry_date, issuer_name = extract_info(certificate_data)

#         if issue_date and expiry_date and issuer_name:
#             # Verify certificate
#             verification_url = re.search(r'https://coursera.org/verify/([A-Z0-9]+)', certificate_data)
#             signature_status = "Certificate has valid verification URL" if verification_url else "No verification URL found"
#             issuer_status = "Issuer is trusted." if check_issuer(issuer_name) else "Issuer is not trusted."
#             expiration_status = "Certificate is valid and not expired." if check_expiration(issue_date, expiry_date) else "Certificate has expired."

#             # Create verification entry
#             verification_entry = {
#                 'timestamp': datetime.now(),
#                 'certificate_data': certificate_data[:200] + "..." if len(certificate_data) > 200 else certificate_data,
#                 'issuer_name': issuer_name,
#                 'issue_date': issue_date,
#                 'expiry_date': expiry_date,
#                 'signature_status': signature_status,
#                 'issuer_status': issuer_status,
#                 'expiration_status': expiration_status
#             }

#             # Add to history
#             st.session_state.history.append(verification_entry)
            
#             # Display current verification results
#             st.success("Certificate verification completed!")
#             st.write(f"**Issuer:** {issuer_name}")
#             st.write(f"**Issue Date:** {issue_date.strftime('%B %d, %Y')}")
#             if verification_url:
#                 st.write(f"**Verification URL:** {verification_url.group(0)}")
#             st.write(f"**Status:**")
#             st.write(signature_status)
#             st.write(issuer_status)
#             st.write(expiration_status)
#         else:
#             st.error("Could not extract required information from the certificate.")
#     except Exception as e:
#         st.error(f"Error processing certificate: {str(e)}")

# # Display verification history
# if st.session_state.history:
#     st.subheader("Verification History")
#     for index, entry in enumerate(reversed(st.session_state.history)):
#         with st.expander(f"Verification {len(st.session_state.history) - index}"):
#             st.write(f"**Verification Time:** {entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
#             st.write(f"**Issuer:** {entry['issuer_name']}")
#             st.write(f"**Issue Date:** {entry['issue_date'].strftime('%B %d, %Y')}")
#             st.write(f"**Signature Status:** {entry['signature_status']}")
#             st.write(f"**Issuer Status:** {entry['issuer_status']}")
#             st.write(f"**Expiration Status:** {entry['expiration_status']}")
# else:
#     st.info("No verification history available.")

# import PyPDF2
# import streamlit as st
# import re
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from datetime import datetime

# def extract_pdf_info(file):
#     reader = PyPDF2.PdfReader(file)
#     text = ''
#     for page in reader.pages:
#         text += page.extract_text() or ''
#     # Clean up extra spaces in the text
#     text = re.sub(r'\s+', ' ', text)
#     return text

# def extract_info(certificate_data):
#     # Debug: Show cleaned certificate data
#     st.write("Cleaned Certificate Text:", certificate_data)
    
#     # Modified patterns for Coursera certificates
#     issue_date = re.search(r'([A-Z][a-z]+)\s+(\d{1,2})\s*,\s*(\d{4})', certificate_data)
#     name = re.search(r'([A-Z\s]+)(?=\s*[A-Za-z\s]+has successfully completed|Su pervised)', certificate_data)
#     course_name = re.search(r'([\w\s:]+)(?=an online non-credit course)', certificate_data)
#     issuer_name = re.search(r'authorized by ([\w\s.,]+) and offered through Coursera', certificate_data)
    
#     # Validation messages
#     validation_messages = []
    
#     if not issue_date:
#         validation_messages.append("⚠️ Could not find issue date - certificate may be invalid")
    
#     if not name:
#         validation_messages.append("⚠️ Could not find recipient name - certificate may be invalid")
    
#     if not course_name:
#         validation_messages.append("⚠️ Could not find course name - certificate may be invalid")
    
#     if not issuer_name:
#         validation_messages.append("⚠️ Could not find issuer information - certificate may be invalid")

#     # Display validation messages
#     for message in validation_messages:
#         st.warning(message)
    
#     try:
#         if issue_date:
#             month, day, year = issue_date.groups()
#             issue_date = datetime.strptime(f"{month} {day} {year}", '%B %d %Y')
#             expiry_date = datetime(issue_date.year + 100, issue_date.month, issue_date.day)
#             issuer = issuer_name.group(1).strip() if issuer_name else "DeepLearning.AI and Stanford University"
#             return issue_date, expiry_date, issuer
#     except Exception as e:
#         st.error(f"Error processing dates: {str(e)}")
    
#     return None, None, None

# def verify_signature(certificate_data):
#     verification_url = re.search(r'https://coursera.org/verify/([A-Z0-9]+)', certificate_data)
#     if not verification_url:
#         st.warning("⚠️ No verification URL found - certificate may be invalid")
#         return False
#     st.write("Verification URL found:", verification_url.group(0))
#     return True

# def check_issuer(issuer_name):
#     if not issuer_name:
#         return False
#     trusted_issuers = ["DeepLearning.AI and Stanford University", "Coursera"]
#     return any(trusted_issuer in issuer_name for trusted_issuer in trusted_issuers)

# def check_expiration(issue_date, expiry_date):
#     if not issue_date or not expiry_date:
#         return False
#     current_date = datetime.now()
#     return current_date < expiry_date

# # Initialize session state for history
# if 'history' not in st.session_state:
#     st.session_state.history = []

# # Streamlit app
# st.title(' Certificate Verifier')

# # File uploader
# uploaded_file = st.file_uploader("Upload your Coursera certificate", type="pdf", key="file_uploader_1")

# if uploaded_file is not None:
#     try:
#         certificate_data = extract_pdf_info(uploaded_file)
        
#         # Extract information
#         issue_date, expiry_date, issuer_name = extract_info(certificate_data)
        
#         # Verify signature (verification URL)
#         is_signature_valid = verify_signature(certificate_data)
        
#         signature_status = "Certificate has valid verification URL" if is_signature_valid else "⚠️ No verification URL found - certificate may be invalid"
        
#         if issue_date and expiry_date and issuer_name:
#             issuer_status = "Issuer is trusted." if check_issuer(issuer_name) else "⚠️ Issuer is not trusted"
#             expiration_status = "Certificate is valid and not expired." if check_expiration(issue_date, expiry_date) else "Certificate has expired."

#             # Create verification entry
#             verification_entry = {
#                 'timestamp': datetime.now(),
#                 'certificate_data': certificate_data[:200] + "..." if len(certificate_data) > 200 else certificate_data,
#                 'issuer_name': issuer_name,
#                 'issue_date': issue_date,
#                 'expiry_date': expiry_date,
#                 'signature_status': signature_status,
#                 'issuer_status': issuer_status,
#                 'expiration_status': expiration_status
#             }

#             # Add to history
#             st.session_state.history.append(verification_entry)
            
#             # Display current verification results
#             st.write(f"**Issuer:** {issuer_name}")
#             st.write(f"**Issue Date:** {issue_date.strftime('%B %d, %Y')}")
#             st.write(f"**Status:**")
#             st.write(signature_status)
#             st.write(issuer_status)
#             st.write(expiration_status)
            
#             if all([is_signature_valid, check_issuer(issuer_name), check_expiration(issue_date, expiry_date)]):
#                 st.success("Certificate verification completed successfully!")
#             else:
#                 st.warning("Certificate verification completed with warnings!")
#         else:
#             st.error("Could not extract required information from the certificate. The certificate may be invalid or in an unsupported format.")
#     except Exception as e:
#         st.error(f"Error processing certificate: {str(e)}")

# # Display verification history
# if st.session_state.history:
#     st.subheader("Verification History")
#     for index, entry in enumerate(reversed(st.session_state.history)):
#         with st.expander(f"Verification {len(st.session_state.history) - index}"):
#             st.write(f"**Verification Time:** {entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
#             st.write(f"**Issuer:** {entry['issuer_name']}")
#             st.write(f"**Issue Date:** {entry['issue_date'].strftime('%B %d, %Y')}")
#             st.write(f"**Signature Status:** {entry['signature_status']}")
#             st.write(f"**Issuer Status:** {entry['issuer_status']}")
#             st.write(f"**Expiration Status:** {entry['expiration_status']}")
# else:
#     st.info("No verification history available.")



# import PyPDF2
# import streamlit as st
# import re
# from datetime import datetime

# def extract_pdf_info(file):
#     reader = PyPDF2.PdfReader(file)
#     text = ''
#     for page in reader.pages:
#         text += page.extract_text() or ''
#     text = re.sub(r'\s+', ' ', text)
#     return text

# def extract_info(certificate_data):
#     st.write("Cleaned Certificate Text:", certificate_data)
    
#     patterns = {
#         'coursera': {
#             'issue_date': r'([A-Z][a-z]+)\s+(\d{1,2})\s*,\s*(\d{4})',
#             'name': r'([A-Z\s]+)(?=\s*[A-Za-z\s]+has successfully completed|Su pervised)',
#             'course_name': r'([\w\s:]+)(?=an online non-credit course)',
#             'issuer': r'authorized by ([\w\s.,]+) and offered through Coursera',
#             'verification': r'https://coursera.org/verify/([A-Z0-9]+)'
#         },
#         'infosys': {
#             'issue_date': r'Issued on: ([A-Za-z]+, [A-Z][a-z]+ \d{1,2}, \d{4})',
#             'name': r'^([A-Z][a-z]+(?: [A-Z][a-z]+)*)',
#             'course_name': r'([\w\s]+)(?=The certicate is awarded to)',
#             'issuer': 'Infosys',
#             'verification': r'https://verify.onwingspan.com'
#         },
#         'simplilearn': {
#             'issue_date': r'(\d{1,2}(?:st|nd|rd|th)\s+[A-Z][a-z]+\s+\d{4})',
#             'name': r'^([A-Z\s]+)',
#             'course_name': r'([\w\s]+)(?=\d{1,2}(?:st|nd|rd|th))',
#             'issuer': 'Simplilearn',
#             'verification': r'Certificate code : (\d+)'
#         },
#         'great_learning': {
#             'verification': r'verify.mygreatlearning.com/([A-Z0-9]+)'
#         }
#     }
    
#     extracted_info = {}
#     certificate_type = None

#     for cert_type, cert_patterns in patterns.items():
#         matches = {key: re.search(pattern, certificate_data) for key, pattern in cert_patterns.items()}
#         if any(matches.values()):
#             certificate_type = cert_type
#             for key, match in matches.items():
#                 if match:
#                     extracted_info[key] = match.group(1)
#             break

#     if not certificate_type:
#         st.error("Unable to determine certificate type. The format may be unsupported.")
#         return None

#     if 'issue_date' in extracted_info:
#         try:
#             if certificate_type == 'coursera':
#                 month, day, year = re.search(patterns['coursera']['issue_date'], extracted_info['issue_date']).groups()
#                 extracted_info['issue_date'] = datetime.strptime(f"{month} {day} {year}", '%B %d %Y')
#             elif certificate_type == 'infosys':
#                 extracted_info['issue_date'] = datetime.strptime(extracted_info['issue_date'], '%A, %B %d, %Y')
#             elif certificate_type == 'simplilearn':
#                 extracted_info['issue_date'] = datetime.strptime(extracted_info['issue_date'], '%d %B %Y')
#             extracted_info['expiry_date'] = datetime(extracted_info['issue_date'].year + 100, extracted_info['issue_date'].month, extracted_info['issue_date'].day)
#         except Exception as e:
#             st.error(f"Error processing dates: {str(e)}")

#     return certificate_type, extracted_info

# def verify_certificate(certificate_type, extracted_info):
#     verification_messages = []

#     required_fields = ['name', 'course_name', 'issue_date', 'verification']
#     for field in required_fields:
#         if field not in extracted_info:
#             verification_messages.append(f"⚠️ Could not find {field.replace('_', ' ')} - certificate may be invalid")

#     if 'verification' in extracted_info:
#         verification_messages.append(f"Verification URL/Code found: {extracted_info['verification']}")

#     if 'issue_date' in extracted_info and 'expiry_date' in extracted_info:
#         if datetime.now() < extracted_info['expiry_date']:
#             verification_messages.append("Certificate is valid and not expired.")
#         else:
#             verification_messages.append("⚠️ Certificate has expired.")

#     trusted_issuers = ["DeepLearning.AI", "Stanford University", "Coursera", "Infosys", "Simplilearn", "Great Learning"]
#     if 'issuer' in extracted_info and any(issuer in extracted_info['issuer'] for issuer in trusted_issuers):
#         verification_messages.append("Issuer is trusted.")
#     else:
#         verification_messages.append("⚠️ Issuer is not trusted or could not be verified.")

#     return verification_messages

# # Streamlit app
# st.title('Multi-Certificate Verifier')

# uploaded_file = st.file_uploader("Upload your certificate (PDF)", type="pdf")

# if uploaded_file is not None:
#     try:
#         certificate_data = extract_pdf_info(uploaded_file)
#         certificate_type, extracted_info = extract_info(certificate_data)

#         if certificate_type and extracted_info:
#             st.subheader("Certificate Information")
#             for key, value in extracted_info.items():
#                 if key not in ['issue_date', 'expiry_date']:
#                     st.write(f"**{key.capitalize()}:** {value}")
            
#             if 'issue_date' in extracted_info:
#                 st.write(f"**Issue Date:** {extracted_info['issue_date'].strftime('%B %d, %Y')}")

#             st.subheader("Verification Results")
#             verification_messages = verify_certificate(certificate_type, extracted_info)
#             for message in verification_messages:
#                 if message.startswith("⚠️"):
#                     st.warning(message)
#                 else:
#                     st.success(message)

#             # Add to history (you can implement this part similar to the original code)

#         else:
#             st.error("Could not extract required information from the certificate. The certificate may be invalid or in an unsupported format.")
#     except Exception as e:
#         st.error(f"Error processing certificate: {str(e)}")

import PyPDF2
import streamlit as st
import re
from datetime import datetime

def extract_pdf_info(file):
    reader = PyPDF2.PdfReader(file)
    text = ''
    for page in reader.pages:
        text += page.extract_text() or ''
    text = re.sub(r'\s+', ' ', text)
    return text
def extract_info(certificate_data):
    st.write("Cleaned Certificate Text:", certificate_data)

    patterns = {
        'coursera': {
            'issue_date': r'([A-Z][a-z]+)\s+(\d{1,2})\s*,\s*(\d{4})',
            'name': r'([A-Z\s]+)(?=\s*[A-Za-z\s]+has successfully completed|Su pervised)',
            'course_name': r'([\w\s:]+)(?=an online non-credit course)',
            'issuer': r'authorized by ([\w\s.,]+) and offered through Coursera',
            'verification': r'https://coursera.org/verify/([A-Z0-9]+)'
        },
        'infosys': {
            'issue_date': r'Issued on: ([A-Za-z]+, [A-Z][a-z]+ \d{1,2}, \d{4})',
            'name': r'^([A-Z][a-z]+(?: [A-Z][a-z]+)*)',
            'course_name': r'([\w\s]+)(?=The certicate is awarded to)',
            'issuer': 'Infosys',
            'verification': r'https://verify.onwingspan.com'
        },
        'simplilearn': {
            'issue_date': r'(\d{1,2}(?:st|nd|rd|th)\s+[A-Z][a-z]+\s+\d{4})',
            'name': r'^([A-Z\s]+)',
            'course_name': r'([\w\s]+)(?=\d{1,2}(?:st|nd|rd|th))',
            'issuer': 'Simplilearn',
            'verification': r'Certificate code : (\d+)'
        },
        'great_learning': {
            'verification': r'verify.mygreatlearning.com/([A-Z0-9]+)'
        }
    }

    extracted_info = {}
    certificate_type = None

    for cert_type, cert_patterns in patterns.items():
        matches = {key: re.search(pattern, certificate_data) for key, pattern in cert_patterns.items()}
        if any(matches.values()):
            certificate_type = cert_type
            for key, match in matches.items():
                if match:
                    extracted_info[key] = match.group(1)
            break

    if not certificate_type:
        st.error("Unable to determine certificate type. The format may be unsupported.")
        return None

    if 'issue_date' in extracted_info:
     try:
        # Convert the issue_date based on certificate type
        if certificate_type == 'coursera':
            date_match = re.search(patterns['coursera']['issue_date'], certificate_data)
            if date_match:
                month, day, year = date_match.groups()
                extracted_info['issue_date'] = datetime.strptime(f"{month} {day} {year}", '%B %d %Y')
        elif certificate_type == 'infosys':
            extracted_info['issue_date'] = datetime.strptime(extracted_info['issue_date'], '%A, %B %d, %Y')
        elif certificate_type == 'simplilearn':
            extracted_info['issue_date'] = datetime.strptime(extracted_info['issue_date'], '%d %B %Y')

        # Generate expiry date (assuming expiry 100 years after issue)
        if isinstance(extracted_info['issue_date'], datetime):
            extracted_info['expiry_date'] = datetime(
                extracted_info['issue_date'].year + 100,
                extracted_info['issue_date'].month,
                extracted_info['issue_date'].day
            )
     except Exception as e:
        st.error(f"Error processing dates: {str(e)}")


    return certificate_type, extracted_info


def verify_certificate(certificate_type, extracted_info):
    verification_messages = []

    required_fields = ['name', 'course_name', 'issue_date', 'verification']
    for field in required_fields:
        if field not in extracted_info:
            verification_messages.append(f"⚠ Could not find {field.replace('_', ' ')} - certificate may be invalid")

    if 'verification' in extracted_info:
        verification_messages.append(f"Verification URL/Code found: {extracted_info['verification']}")

    if 'issue_date' in extracted_info and 'expiry_date' in extracted_info:
        if datetime.now() < extracted_info['expiry_date']:
            verification_messages.append("Certificate is valid and not expired.")
        else:
            verification_messages.append("⚠ Certificate has expired.")

    trusted_issuers = ["DeepLearning.AI", "Stanford University", "Coursera", "Infosys", "Simplilearn", "Great Learning"]
    if 'issuer' in extracted_info and any(issuer in extracted_info['issuer'] for issuer in trusted_issuers):
        verification_messages.append("Issuer is trusted.")
    else:
        verification_messages.append("⚠ Issuer is not trusted or could not be verified.")

    return verification_messages

# Streamlit app
st.title('🎨 Multi-Certificate Verifier')

# Session state to store history of verified certificates
if 'history' not in st.session_state:
    st.session_state.history = []

uploaded_file = st.file_uploader("📁 Upload your certificate (PDF)", type="pdf")
if uploaded_file is not None:
    try:
        certificate_data = extract_pdf_info(uploaded_file)
        certificate_type, extracted_info = extract_info(certificate_data)

        if certificate_type and extracted_info:
            st.subheader("Certificate Information")
            for key, value in extracted_info.items():
                if key not in ['issue_date', 'expiry_date']:
                    st.write(f"{key.capitalize()}:** {value}")
            
            if 'issue_date' in extracted_info:
                st.write(f"Issue Date: {extracted_info['issue_date'].strftime('%B %d, %Y')}")

            st.subheader("🔍 Verification Results")
            verification_messages = verify_certificate(certificate_type, extracted_info)
            for message in verification_messages:
                if message.startswith("⚠"):
                    st.warning(message)
                else:
                    st.success(message)

            # Add to history
            st.session_state.history.append({
                'certificate_type': certificate_type,
                'name': extracted_info.get('name'),
                'course_name': extracted_info.get('course_name'),
                'issue_date': extracted_info.get('issue_date').strftime('%B %d, %Y') if 'issue_date' in extracted_info else 'N/A',
                'verification': extracted_info.get('verification')
            })

        else:
            st.error("Could not extract required information from the certificate. The certificate may be invalid or in an unsupported format.")
    except Exception as e:
        st.error(f"Error processing certificate: {str(e)}")

# Display verification history
with st.sidebar:
 if st.session_state.history:
    st.subheader("🔄 Verification History")
    for idx, history_item in enumerate(st.session_state.history, 1):
        st.write(f"{idx}. Certificate Type:** {history_item['certificate_type']}")
        st.write(f"Name: {history_item['name']}")
        st.write(f"Course Name: {history_item['course_name']}")
        st.write(f"Issue Date: {history_item['issue_date']}")
        st.write(f"Verification: {history_item['verification']}")
        st.write("---")
 else:
        st.write("No certificates verified yet.")
