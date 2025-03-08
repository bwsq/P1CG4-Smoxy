import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import openai
import os
import timeit

os.environ["TOKENIZERS_PARALLELISM"] = "false"

embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


def load_precomputed_data(index_file="faiss_index.bin", descriptions_file="cve_descriptions.json"):
    # Load precomputed FAISS index
    index = faiss.read_index(index_file)

    # Load descriptions (in the same order as FAISS index)
    with open(descriptions_file, 'r', encoding='utf-8') as f:
        descriptions = json.load(f)

    return index, descriptions

index, descriptions = load_precomputed_data()

def intercept_simulated_traffic():
    return """{
  "id": 6,
  "type": "response",
  "status_code": 301,
  "reason": "",
  "headers": {
    "date": "Wed, 05 Mar 2025 10:23:08 GMT",
    "server": "mw-web.codfw.main-79b64dbb99-gsskr",
    "location": "https://www.wikipedia.org/",
    "content-length": "234",
    "content-type": "text/html; charset=iso-8859-1",
    "vary": "X-Forwarded-Proto",
    "age": "830",
    "x-cache": "cp5020 miss, cp5020 hit/3788",
    "x-cache-status": "hit-front",
    "server-timing": "cache;desc=\"hit-front\", host;desc=\"cp5020\"",
    "strict-transport-security": "max-age=106384710; includeSubDomains; preload",
    "report-to": "{ \"group\": \"wm_nel\", \"max_age\": 604800, \"endpoints\": [{ \"url\": \"https://intake-logging.wikimedia.org/v1/events?stream=w3c.reportingapi.network_error&schema_uri=/w3c/reportingapi/network_error/1.0.0\" }] }",
    "nel": "{ \"report_to\": \"wm_nel\", \"max_age\": 604800, \"failure_fraction\": 0.05, \"success_fraction\": 0.0}",
    "set-cookie": "WMF-Last-Access=05-Mar-2025;Path=/;HttpOnly;secure;Expires=Sun, 06 Apr 2025 00:00:00 GMT, WMF-Last-Access-Global=05-Mar-2025;Path=/;Domain=.wikipedia.org;HttpOnly;secure;Expires=Sun, 06 Apr 2025 00:00:00 GMT, GeoIP=SG::Singapore:1.35:103.70:v4; Path=/; secure; Domain=.wikipedia.org, NetworkProbeLimit=0.001;Path=/;Secure;SameSite=Lax;Max-Age=3600",
    "x-client-ip": "101.127.156.242"
  },
  "http_version": "HTTP/2.0",
  "content-type": "text/html; charset=iso-8859-1",
  "content": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n <head>\n  <title>\n   301 Moved Permanently\n  </title>\n </head>\n <body>\n  <h1>\n   Moved Permanently\n  </h1>\n  <p>\n   The document has moved\n   <a href=\"https://www.wikipedia.org/\">\n    here\n   </a>\n   .\n  </p>\n </body>\n</html>\n"
}"""


def retrieve_related_cves(intercepted_text, index, descriptions, model):
    query_embedding = model.encode([intercepted_text])
    D, I = index.search(np.array(query_embedding), k=2)
    return [descriptions[i] for i in I[0]]


def build_rag_prompt(intercepted_text, matched_cves):
    cve_list_text = "\n".join(matched_cves)

    prompt = f"""
You're a web browser proxy expert that is helping the user examine web content.
The following web content stored as a dictionary was intercepted :

{intercepted_text}

Provide a summary of what the web content is for in less than 100 words and begin the summary with.
"The intercepted content suggests that this is a "

Now use ##summary## to end off this paragraph.

Then flag it as either benign, suspicious or malicious (beign, suspicious or malicious)

Now use ##flag## to end off this section


If you flagged the content as suspicious or malicious give a reason
considerations of possible CVE can be examined with FAISS CVE retrieval system  possibly relevant vulnerabilities findings.
{cve_list_text} If you deem the CVE irrelevant, then ignore it and do not generate a response for the CVE.
if you deem the CVE relevant then start of your response paragraph with "Upon examining the content".


Now use ##reason## to end off this section

If you flagged the content as suspicious or malicious provide possible remediation 

Now use ##remediation## to end off this section

If you flagged the content as suspicious or malicious provide a payload we can use to test.
Now use ##payload## to end off this section

Any Remediation and/or payload should follow the current dictionary structure.

"""
    return prompt


def query_llm(prompt):
    openai.api_key = "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"  # Replace with your real key

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst reviewing intercepted web traffic."},
            {"role": "user", "content": prompt}
        ]
    )
    return response['choices'][0]['message']['content']


if __name__ == "__main__":
    start = timeit.timeit()  # debug
    intercepted_content = intercept_simulated_traffic()
    matched_cves = retrieve_related_cves(intercepted_content, index, descriptions, embedding_model)
    rag_prompt = build_rag_prompt(intercepted_content, matched_cves)
    # print("\nGenerated Prompt for LLM :\n")
    # print(rag_prompt)

    try:
        llm_response = query_llm(rag_prompt)
        print("\nLLM Analysis Response:\n")
        print(llm_response)
        end = timeit.timeit() #debug
        print(end - start) #debug


    except Exception as e:
        print(f"LLM query failed: {e}")

# specify embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
# load precomputed data load_precomputed_data()

# function call ---
# find matched_cves = retrieve_related_cves(intercepted_content, index, descriptions, embedding_model)
# rag_prompt = build_rag_prompt(intercepted_content, matched_cves)
# call API llm_response = query_llm(rag_prompt)
