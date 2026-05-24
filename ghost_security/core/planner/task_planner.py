"""
Ghost Security Platform — Task Planner
Real LLM-powered task decomposition and planning. No placeholders.
"""
import json
from typing import Dict, List, Optional
from pathlib import Path
from openai import OpenAI

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_MODEL


PLANNER_SYSTEM = """You are a security audit planner. Given a target (repository, file, URL, binary),
create a structured audit plan with concrete steps.

Each step must be:
- Specific and actionable
- Ordered by dependency
- Assigned to the right specialist agent

Output valid JSON only. No markdown, no explanation outside JSON.
"""


class TaskPlanner:
    """
    Real LLM-powered planner that decomposes security audit tasks.
    """

    def __init__(self):
        self.llm = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)

    def create_plan(self, target: str, audit_type: str = "full") -> Dict:
        """
        Create a real audit plan using LLM reasoning.
        Returns structured plan with steps and agent assignments.
        """
        prompt = f"""Create a security audit plan for:
Target: {target}
Audit type: {audit_type}

Return JSON with this structure:
{{
  "target": "{target}",
  "audit_type": "{audit_type}",
  "estimated_steps": <number>,
  "steps": [
    {{
      "id": 1,
      "name": "step name",
      "description": "what to do",
      "agent": "research|security|coding|reviewer",
      "tools": ["tool1", "tool2"],
      "depends_on": [],
      "priority": "high|medium|low"
    }}
  ],
  "focus_areas": ["area1", "area2"]
}}"""

        try:
            response = self.llm.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": PLANNER_SYSTEM},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            plan_text = response.choices[0].message.content
            plan = json.loads(plan_text)
            return plan
        except Exception as e:
            # Fallback plan if LLM fails
            return self._default_plan(target, audit_type, str(e))

    def _default_plan(self, target: str, audit_type: str, error: str) -> Dict:
        """Default plan when LLM is unavailable."""
        return {
            "target": target,
            "audit_type": audit_type,
            "estimated_steps": 5,
            "error": error,
            "steps": [
                {"id": 1, "name": "Reconnaissance", "description": "Gather information about target",
                 "agent": "research", "tools": ["list_directory", "read_file"], "depends_on": [], "priority": "high"},
                {"id": 2, "name": "Static Analysis", "description": "Run static security scanners",
                 "agent": "security", "tools": ["run_command"], "depends_on": [1], "priority": "high"},
                {"id": 3, "name": "Code Review", "description": "Manual code review for vulnerabilities",
                 "agent": "security", "tools": ["read_file", "run_command"], "depends_on": [1], "priority": "high"},
                {"id": 4, "name": "Secret Detection", "description": "Find hardcoded secrets and credentials",
                 "agent": "security", "tools": ["run_command"], "depends_on": [1], "priority": "high"},
                {"id": 5, "name": "Report Generation", "description": "Compile findings into report",
                 "agent": "reviewer", "tools": ["write_file"], "depends_on": [2, 3, 4], "priority": "medium"}
            ],
            "focus_areas": ["authentication", "injection", "secrets", "dependencies"]
        }

    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity and impact."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))
