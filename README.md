# PolySwarm Scripts

This is a central location used to store single-use scripts created by Customer Success at PolySwarm, utilising PolySwarm's public API. 

The API in question can be found on our documentation website at: https://docs.polyswarm.io

**CURRENT FOLDER STRUCTURE**

*/ai-model-outreach*

* This script will use the IOC Search functionality to output a list of hashes that reach out to the top known LLMs; further research should be carried out to understand if these are malicious. Note that these samples have been sandboxed, hence have been seen to communicate with live llm urls.

* Files: search_ai_malware.py (Download script locally, add your api key and run)
* Files: llm_domain_hash_search_results.json (produced output from above script)

