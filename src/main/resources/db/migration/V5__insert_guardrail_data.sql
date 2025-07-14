-- Insert initial guardrail data

-- Insert Guardrail entities
INSERT INTO guardrail (id, name, description, scope, external_references, metadata_keys, instructions) VALUES
(1, 'Guardrails.ai', 'Python SDK with input/output validation: toxicity, bias, hallucination, format/schema enforcement', 'BOTH', 
 '{"https://github.com/guardrails-ai/guardrails"}', 
 '{"sources", "embed_function", "pii_entities"}',
 '## Installation
```bash
pip install guardrails-ai
```

## Basic Usage
```python
import guardrails as gd

# Define guardrails schema
guard = gd.Guard.from_string(
    validators=[
        gd.validators.ToxicLanguage(),
        gd.validators.BiasCheck(),
        gd.validators.AntiHallucination()
    ]
)

# Validate input
result = guard.validate("Your input text here")
```

## Configuration Parameters
- **sources**: Data sources for validation context
- **embed_function**: Custom embedding function for semantic validation
- **pii_entities**: Personal identifiable information entities to detect

## Error Handling
```python
try:
    result = guard.validate(content)
    if not result.passed:
        return {"error": "Content violates safety guidelines"}
except Exception as e:
    logger.error(f"Guardrail error: {e}")
    return {"error": "Validation service unavailable"}
```'),

(2, 'NeMo Guardrails', 'Programmable DSL-based SDK: input, output, RAG fact-checking, bias/equality flows', 'BOTH', 
 '{"https://docs.nvidia.com/nemo/guardrails/latest/index.html"}', 
 '{"knowledge_base", "rag_documents"}',
 '## Installation
```bash
pip install nemoguardrails
```

## Basic Usage
```python
from nemoguardrails import LLMRails, RailsConfig

# Load configuration
config = RailsConfig.from_path("path/to/config")
app = LLMRails(config)

# Apply guardrails
response = app.generate(messages=[{
    "role": "user", 
    "content": "Your input message"
}])
```

## Configuration Parameters
- **knowledge_base**: Knowledge base for fact-checking
- **rag_documents**: RAG documents for context validation

## Integration Pattern
```python
# Pre-processing: Apply input guardrails before sending to LLM
# Post-processing: Apply output guardrails after receiving LLM response
# Monitoring: Log guardrail violations for analysis and improvement
```'),

(3, 'Llama Guard 3‑8B', 'Advanced safety classifier (8 B params) for both input/output moderation, multilingual (8 languages), tool-use aware (search, code), with high F1 (0.939) and low FPR (0.040)', 'BOTH', 
 '{"https://huggingface.co/meta-llama/Llama-Guard-3-8B"}', 
 '{"model_variant", "quantized", "languages_supported"}',
 '## Installation
```bash
pip install transformers torch
```

## Basic Usage
```python
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# Load model and tokenizer
model_id = "meta-llama/Llama-Guard-3-8B"
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16)

# Classify content
def classify_content(text):
    inputs = tokenizer(text, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(**inputs, max_new_tokens=100)
    return tokenizer.decode(outputs[0], skip_special_tokens=True)
```

## Configuration Parameters
- **model_variant**: Model variant selection (base, instruct, etc.)
- **quantized**: Enable quantization for reduced memory usage
- **languages_supported**: Configure supported languages for multilingual use

## Performance Considerations
- Cache guardrail models to avoid repeated loading
- Consider async processing for multiple validations
- Implement timeout mechanisms for guardrail execution'),

(4, 'Detoxify', 'Transformer‑based output toxicity detection: insults, identity hate, severe toxicity', 'OUTPUT', 
 '{"https://github.com/unitaryai/detoxify"}', 
 '{}',
 '## Installation
```bash
pip install detoxify
```

## Basic Usage
```python
from detoxify import Detoxify

# Initialize detector
detector = Detoxify(''original'')

# Detect toxicity
results = detector.predict("Your text to analyze")
print(results)
# Output: {''toxicity'': 0.1, ''severe_toxicity'': 0.05, ''obscene'': 0.03, ...}
```

## Configuration Parameters
No specific configuration parameters required - uses pre-trained models.

## Integration Example
```python
def validate_output(text):
    detector = Detoxify(''original'')
    results = detector.predict(text)
    
    # Check if any toxicity score exceeds threshold
    if any(score > 0.7 for score in results.values()):
        return {"safe": False, "scores": results}
    return {"safe": True, "scores": results}
```');

-- Insert Guardrail Metrics relationships
INSERT INTO guardrail_metrics (guardrail_id, task_metric_id) VALUES
-- Guardrails.ai metrics
(1, 4),  -- amb_bias_score_Age
(1, 5),  -- disamb_bias_score_Age
(1, 6),  -- amb_bias_score_Gender_identity
(1, 7),  -- disamb_bias_score_Gender_identity
(1, 8),  -- amb_bias_score_Race_ethnicity
(1, 9),  -- disamb_bias_score_Race_ethnicity
(1, 10), -- pct_stereotype
(1, 11), -- acc (truthfulqa_mc1)
(1, 12), -- acc_norm (truthfulqa_mc1)
(1, 13), -- acc (toxigen)
(1, 14), -- acc_norm (toxigen)
(1, 15), -- acc (ethics_cm)
(1, 16), -- acc_norm (ethics_cm)
(1, 17), -- acc (winogender)
(1, 18), -- acc_norm (winogender)

-- NeMo Guardrails metrics
(2, 4),  -- amb_bias_score_Age
(2, 5),  -- disamb_bias_score_Age
(2, 6),  -- amb_bias_score_Gender_identity
(2, 7),  -- disamb_bias_score_Gender_identity
(2, 8),  -- amb_bias_score_Race_ethnicity
(2, 9),  -- disamb_bias_score_Race_ethnicity
(2, 10), -- pct_stereotype
(2, 11), -- acc (truthfulqa_mc1)
(2, 12), -- acc_norm (truthfulqa_mc1)
(2, 15), -- acc (ethics_cm)
(2, 16), -- acc_norm (ethics_cm)
(2, 17), -- acc (winogender)
(2, 18), -- acc_norm (winogender)

-- Llama Guard metrics
(3, 4),  -- amb_bias_score_Age
(3, 5),  -- disamb_bias_score_Age
(3, 6),  -- amb_bias_score_Gender_identity
(3, 7),  -- disamb_bias_score_Gender_identity
(3, 8),  -- amb_bias_score_Race_ethnicity
(3, 9),  -- disamb_bias_score_Race_ethnicity
(3, 10), -- pct_stereotype
(3, 11), -- acc (truthfulqa_mc1)
(3, 12), -- acc_norm (truthfulqa_mc1)
(3, 13), -- acc (toxigen)
(3, 14), -- acc_norm (toxigen)
(3, 15), -- acc (ethics_cm)
(3, 16), -- acc_norm (ethics_cm)
(3, 17), -- acc (winogender)
(3, 18), -- acc_norm (winogender)

-- Detoxify metrics
(4, 13), -- acc (toxigen)
(4, 14); -- acc_norm (toxigen)

-- Update sequence values to prevent conflicts with existing data
SELECT setval('guardrail_SEQ', (SELECT MAX(id) FROM guardrail) + 1); 
