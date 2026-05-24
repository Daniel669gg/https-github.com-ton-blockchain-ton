"""
Ghost Security Platform — Self-Healing Loop
Retry with exponential backoff and error diagnosis.
"""
import asyncio
from typing import Callable, Dict, Optional


class SelfHealingLoop:
    async def repair(self, executor, verifier, task: str, retries: int = 5,
                     backoff_base: float = 1.5, on_retry: Optional[Callable] = None) -> Dict:
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                result = await executor.execute(task)
                verification = await verifier.verify(result)
                if verification.get("passed"):
                    return result
                last_error = verification.get("reason", "Verification failed")
                if on_retry:
                    on_retry(attempt, last_error)
                if attempt < retries:
                    await asyncio.sleep(backoff_base ** attempt)
            except Exception as exc:
                last_error = str(exc)
                if on_retry:
                    on_retry(attempt, last_error)
                if attempt < retries:
                    await asyncio.sleep(backoff_base ** attempt)
        raise RuntimeError(f"Self-healing failed after {retries} attempts. Last: {last_error}")
