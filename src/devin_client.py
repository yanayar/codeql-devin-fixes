"""
Devin API client for triggering security fix sessions.

"""

class DevinClient:

    def __init__(self, api_key: str, base_url: str = "https://api.devin.ai/v1"):
        self.api_key = api_key
        self.base_url = base_url
    
    
