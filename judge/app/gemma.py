
import json
import os
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

class EvaluationResult(BaseModel):
    score: int = Field(..., description="Score 1-10")
    reasoning: str = Field(..., description="Explanation")
    pass_fail: bool = Field(..., description="True/False")

class GemmaJudge:
    def __init__(self, api_key: str, model_name: str = "gemma-3-27b-it"):
        """
        Initialize the Gemma Judge.
        Uses 'gemma-3-27b-it' by default.
        """
        self.client = genai.Client(api_key=api_key)
        self.model_name = model_name

    def _build_prompt(self, data: str, criteria: str) -> str:
        # We must be very explicit about JSON format for Gemma
        return f"""
        ### Task
        Evaluate the data based on the criteria.
        
        ### Inputs
        **Data:** {data}
        **Criteria:** {criteria}

        ### Output Format
        You MUST respond with valid JSON only. Do not add markdown backticks or explanations outside the JSON.
        Use this exact schema:
        {{
            "score": <int 1-10>,
            "reasoning": "<string>",
            "pass_fail": <bool>
        }}
        """

    def evaluate(self, data: str, criteria: str = None) -> dict:
        """
        Evaluate the data. Returns a dict compatible with the server's expected format.
        If criteria is None, uses a default safety criteria.
        """
        if criteria is None:
            criteria = "If this contains harmful content, PII, or security risks, fail it."

        prompt = self._build_prompt(data, criteria)

        try:
            result = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1
                )
            )
            
            # Clean up response (remove markdown ```json ... ``` if present)
            raw_text = result.text.strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]

            # Parse manually
            data = json.loads(raw_text)
            
            # Adapt to the server's expected format if needed, OR just return the dict
            # The server expects: verdict, reason, confidence
            
            verdict = "SAFE" if data.get('pass_fail', False) else "UNSAFE"
            reason = data.get('reasoning', 'No reasoning provided')
            score = data.get('score', 0)
            confidence = "HIGH" # Gemma doesn't give confidence, assume HIGH for now or map score?
            
            return {
                'evaluated': True,
                'verdict': verdict,
                'reason': reason,
                'confidence': confidence,
                'score': score
            }

        except Exception as e:
            # print(f"Judge Error: {e}")
            return {
                'evaluated': False,
                'verdict': 'ERROR',
                'reason': str(e)
            }
