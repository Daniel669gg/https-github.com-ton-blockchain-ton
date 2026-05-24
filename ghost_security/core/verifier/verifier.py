import json
import os
from openai import OpenAI
from config.config import LLM_MODEL, OPENAI_BASE_URL

class AgentVerifier:
    """Verifier that critiques agent's findings to reduce false positives"""
    
    def __init__(self):
        self.client = OpenAI(base_url=OPENAI_BASE_URL)
        
    def verify_findings(self, task, findings):
        """Critique the findings and filter out false positives"""
        prompt = f"""
        TASK: {task}
        PROPOSED FINDINGS:
        {json.dumps(findings, indent=2)}
        
        You are a Senior Security Auditor. Your job is to CRITIQUE these findings.
        For each finding:
        1. Is it a real vulnerability or a false positive?
        2. Is the severity correct?
        3. Is the recommendation practical?
        
        Return a refined list of findings in JSON format only. 
        If a finding is likely a false positive, remove it.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "system", "content": "You are a critical security verifier. Output ONLY valid JSON."},
                          {"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            return json.loads(content).get("findings", findings)
        except Exception as e:
            print(f"Verification error: {e}")
            return findings
