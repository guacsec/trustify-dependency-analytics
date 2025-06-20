# Model Cards REST API

There are 2 endpoints one for query the existing reports and another one to retrieve the full report.

The database contains only 2 reports.

Model name|UUID
----------|----
microsoft/phi-2|550e8400-e29b-41d4-a716-446655440004
meta-llama/Llama-3.1-8B-Instruct|550e8400-e29b-41d4-a716-446655440005


## Query model reports

This endpoint helps rendering the model cards for multiple model names.

```
POST /api/v4/model-cards HTTP/1.1

{
    "queries": [
        {
            "model_name": "microsoft/phi-2"
        },
        {
            "model_name": "meta-llama/Llama-3.1-8B-Instruct"
        }
    ]
}
```

The response for this request can be found [here](./responses/query-response.json)

It contains an array of results with the following data:

- ID
- Report name
- Model name
- Metrics
  - Task name
  - Metric name
  - Score
  - Assessment (calculated from the thresholds)

## Retrieve model report by UUID

Gets a full report from a given UUID.

```
GET /api/v4/model-cards/{report_id}
```

Will return a full report containing the following information:

- ID
- Report name (example: Llama-3.1-8B-Instruct Evaluation Report)
- How the report was generated (batch_size, lm_eval_version, etc.)
- Tasks
  - Name
  - Description
  - Tags
  - Metrics
    - name
    - score
    - higher_is_better
    - categories (Custom list of categories where the metric can fit in)
    - thresholds
      - upper
      - lower
      - name (Moderate)
      - interpretation (Understands many facts, but still susceptible to misinformation or overconfidence.)
      - category (this helps knowing how many thresholds are defined)

See the 2 possible responses here:

- [microsoft/phi-2](./responses/phi-2.json)
- [meta-llama/Llama-3.1-8B-Instruct](./responses/llama-3.1-8B-Instruct.json)

