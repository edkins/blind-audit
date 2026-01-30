
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock libraries that might not be installed in this env
sys.modules['google'] = MagicMock()
sys.modules['google.genai'] = MagicMock()
sys.modules['google.genai.types'] = MagicMock()
sys.modules['datasets'] = MagicMock()
sys.modules['flask'] = MagicMock()
sys.modules['cryptography'] = MagicMock()
sys.modules['cryptography.hazmat'] = MagicMock()
sys.modules['cryptography.hazmat.primitives'] = MagicMock()
sys.modules['cryptography.hazmat.primitives.asymmetric'] = MagicMock()
sys.modules['cryptography.x509'] = MagicMock()
sys.modules['cryptography.hazmat.backends'] = MagicMock()
sys.modules['pynacl'] = MagicMock()

# Setup paths (assuming running from project root)
import os
sys.path.append(os.path.abspath("judge/app"))
sys.path.append(os.path.abspath("data-provider/app"))

# Now try imports
try:
    print("Testing imports...")
    import gemma
    import dataset
    print("Imports successful!")
except ImportError as e:
    print(f"Import failed: {e}")
    sys.exit(1)

class TestIntegration(unittest.TestCase):
    def test_gemma_judge_init(self):
        """Test GemmaJudge initialization and evaluation logic"""
        judge = gemma.GemmaJudge(api_key="fake_key")
        
        # Mock the client response
        mock_response = MagicMock()
        mock_response.text = '```json\n{"score": 8, "reasoning": "Safe", "pass_fail": true}\n```'
        judge.client.models.generate_content.return_value = mock_response
        
        result = judge.evaluate("some data")
        
        self.assertEqual(result['verdict'], 'SAFE')
        self.assertEqual(result['score'], 8)
        self.assertEqual(result['confidence'], 'HIGH')
        print("Gemma Judge test passed")

    @patch('dataset.load_dataset')
    def test_dataset_fetch(self, mock_load_dataset):
        """Test dataset fetching logic"""
        mock_data = MagicMock()
        # Create a mock object that supports .take()
        mock_take = MagicMock()
        mock_take.__iter__.return_value = [
            {'source_text': 'test text 1', 'privacy_mask': []},
            {'source_text': 'test text 2', 'privacy_mask': []}
        ]
        mock_data.take.return_value = mock_take
        mock_load_dataset.return_value = mock_data
        
        # Test with explicit token
        import os
        os.environ['HF_TOKEN'] = 'test_token'
        
        results = dataset.parse_dataset(entries=2)
        
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['text'], 'test text 1')
        mock_load_dataset.assert_called_with("ai4privacy/pii-masking-200k", split="train", streaming=True, token='test_token')
        print("Dataset test passed")

if __name__ == '__main__':
    unittest.main()
