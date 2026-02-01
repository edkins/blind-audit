from datasets import load_dataset
import io

def get_dataset(token=None):
    # Use ai4privacy/pii-masking-200k or similar
    # Loading streaming=True to avoid downloading the whole thing
    return load_dataset("ai4privacy/pii-masking-200k", split="train", streaming=True, token=token)

def parse_dataset(entries=10, dataset=None):
    if dataset is None:
        try:
            dataset = get_dataset()
        except Exception as e:
            print(f"Failed to load HF dataset: {e}")
            return []
        
    results = []
    try:
        # ai4privacy/pii-masking-200k structure:
        # features: ['source_text', 'target_text', 'privacy_mask', ...]
        for i, sample in enumerate(dataset.take(entries)):
            text = sample.get('source_text', '')
            # We also get the ground truth if we ever want to use it for internal validation
            pii_entries = sample.get('privacy_mask', [])
            
            if text:
                results.append({
                    'text': text,
                    'pii_entries': pii_entries
                })
    except Exception as e:
        print(f"Error parsing dataset iteration: {e}")
        return []

    return results

def generate_synthetic_dataset(entries=10):
    """Generate simple synthetic PII data for testing without internet."""
    templates = [
        "My name is {name} and my email is {email}.",
        "Please send the package to {address}.",
        "Contact me at {phone}.",
        "Here is a regular sentence with no PII.",
    ]
    
    import random
    names = ["Alice", "Bob", "Charlie", "David"]
    emails = ["alice@example.com", "bob@test.org", "charlie@corp.net"]
    addresses = ["123 Main St", "456 Oak Ave", "789 Pine Rd"]
    phones = ["555-0100", "555-0101", "555-0102"]
    
    results = []
    for _ in range(entries):
        tmpl = random.choice(templates)
        text = tmpl.format(
            name=random.choice(names),
            email=random.choice(emails),
            address=random.choice(addresses),
            phone=random.choice(phones)
        )
        results.append({'text': text, 'pii_entries': []}) # Dummy ground truth
        
    return results
