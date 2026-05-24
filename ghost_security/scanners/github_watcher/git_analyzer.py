import subprocess
import os
import re

class GitDeepAnalyzer:
    """Advanced Git history analyzer for security patterns"""
    
    def __init__(self, repo_path):
        self.repo_path = repo_path
        
    def find_suspicious_commits(self, n=50):
        """Find commits that might be related to security fixes or vulnerabilities"""
        cmd = [
            "git", "-C", self.repo_path, "log", 
            f"-{n}", "--pretty=format:%H|%an|%s", "--no-color"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            commits = []
            for line in result.stdout.split('\n'):
                if '|' in line:
                    h, author, msg = line.split('|', 2)
                    # Check for security keywords
                    if re.search(r'fix|security|vuln|leak|patch|cve|overflow', msg, re.I):
                        commits.append({
                            "hash": h,
                            "author": author,
                            "message": msg,
                            "suspicious": True
                        })
            return commits
        except Exception:
            return []
            
    def get_blame_info(self, file_path, line_number):
        """Get who changed a specific line (useful for identifying vulnerability origin)"""
        cmd = [
            "git", "-C", self.repo_path, "blame", 
            "-L", f"{line_number},{line_number}", "--porcelain", file_path
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            lines = result.stdout.split('\n')
            if lines:
                commit_hash = lines[0].split()[0]
                author = next((l.split(' ', 1)[1] for l in lines if l.startswith('author ')), "Unknown")
                return {"hash": commit_hash, "author": author}
        except Exception:
            pass
        return None
