# src/llm.py
import logging, os, re, time
from typing import Dict, Optional
from google import genai
from google.genai import types, errors

logger = logging.getLogger(__name__)

def refine_with_llm(
    prompt: str,
    ask_sage_client,
    *,
    provider_pref: Optional[str],
    model: Optional[str],
    max_retries: int = 3,
    retry_delay: int = 1,
    gemini_primary_model: Optional[str] = None,
) -> Dict[str, str]:
    """
    Shared LLM call surface. Returns:
      {"text": <output>, "endpoint": "gemini" | "asksage", "model_used": <name>}
    """
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Prompt must be a non-empty string")

    def _call_gemini(gem_model: str) -> Dict[str, str]:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=gem_model,
            contents=[types.Content(role="user", parts=[types.Part.from_text(text=prompt)])],
            config=types.GenerateContentConfig(temperature=0.7),
        )
        if not resp or not getattr(resp, "text", None):
            raise ValueError("Invalid/empty response from Gemini")
        return {"text": resp.text, "endpoint": "gemini", "model_used": gem_model}

    def _call_asksage(as_model: str) -> Dict[str, str]:
        resp = ask_sage_client.query(
            prompt, persona="default", dataset="none",
            limit_references=0, temperature=0.7, live=0,
            model=as_model, system_prompt=None,
        )
        if not resp or not isinstance(resp, dict) or not resp.get("message"):
            raise ValueError("Invalid/empty response from AskSage")
        return {"text": resp["message"], "endpoint": "asksage", "model_used": as_model}

    if provider_pref in {"gemini", "asksage"} and model:
        return _call_gemini(model) if provider_pref == "gemini" else _call_asksage(model)

    primary_gemini_model = gemini_primary_model or (model if model else "gemini-2.5-pro")
    for attempt in range(max_retries):
        try:
            return _call_gemini(primary_gemini_model)
        except (errors.ClientError, errors.APIError, ValueError) as e:
            msg = str(e); code = getattr(e, "status_code", None)
            retriable = code == 429 or "429" in msg or "RESOURCE_EXHAUSTED" in msg or "quota" in msg.lower() or "rate" in msg.lower()
            if retriable:
                break
            delay = retry_delay * (2 ** attempt)
            m = re.search(r'retry in (\d+(?:\.\d+)?)', msg.lower())
            if m:
                try: delay = min(float(m.group(1)) + 1, 120)
                except: pass
            if attempt < max_retries - 1:
                time.sleep(delay)
    return _call_asksage("google-gemini-2.5-pro")
