from datasets import load_dataset
import json
import os

def get_dataset(token=None):
    if token is None:
        token = os.environ.get("HF_TOKEN")
    
    # If still None, load_dataset might work if dataset is public, or fail if private/gated.
    # The original had a specific token, implying it might be needed.
    return load_dataset("ai4privacy/pii-masking-200k", split="train", streaming=True, token=token)

def parse_dataset(entries=5, dataset=None):
    if dataset is None:
        dataset = get_dataset()
        
    results = []
    try:
        for i, sample in enumerate(dataset.take(entries)):
            # The 'source_text' is the raw email/chat
            # The 'privacy_mask' is the list of sensitive entities (Ground Truth)
            text = sample['source_text']
            pii_entries = sample['privacy_mask']
            results.append({
                'text': text,
                'pii_entries': pii_entries
            })
    except Exception as e:
        print(f"Error parsing dataset: {e}")
        return []

    return results
