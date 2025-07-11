-- Insert initial report data for Model Card entities

-- Insert available Model Card Reports
INSERT INTO model_card_report (
    id, name, source, 
    model_name, model_revision, model_sha, model_source, d_type, batch_size, 
    batch_sizes, lm_eval_version, transformers_version
) VALUES 
(
    '550e8400-e29b-41d4-a716-446655440004',
    'Phi-2 Evaluation Report',
    'microsoft',
    'microsoft/phi-2',
    'main',
    'sha256:ef382358ec9e382308935a992d908de099b64c23',
    'hf',
    'torch.float16',
    'auto',
    '{64}',
    '0.4.8',
    '4.51.3'
),
(
    '550e8400-e29b-41d4-a716-446655440005',
    'Llama-3.1-8B-Instruct Evaluation Report',
    'meta',
    'meta-llama/Llama-3.1-8B-Instruct',
    'main',
    'sha256:0e9e39f249a16976918f6564b8830bc894c89659',
    'hf',
    'torch.bfloat16',
    '2',
    '{2}',
    '0.4.8',
    '4.51.3'
);

-- Insert Report Model Card Tasks
INSERT INTO model_card_task (id, report_id, task_id) VALUES
-- Phi-2 model evaluation results
(1, '550e8400-e29b-41d4-a716-446655440004', 1), -- bbq
(2, '550e8400-e29b-41d4-a716-446655440004', 2), -- crows_pairs_english  
(3, '550e8400-e29b-41d4-a716-446655440004', 4), -- toxigen
(4, '550e8400-e29b-41d4-a716-446655440004', 3), -- truthfulqa_mc1
(5, '550e8400-e29b-41d4-a716-446655440004', 6), -- winogender
-- Llama-3.1-8B-Instruct model evaluation results
(6, '550e8400-e29b-41d4-a716-446655440005', 1), -- bbq
(7, '550e8400-e29b-41d4-a716-446655440005', 2), -- crows_pairs_english
(8, '550e8400-e29b-41d4-a716-446655440005', 5), -- ethics_cm
(9, '550e8400-e29b-41d4-a716-446655440005', 4), -- toxigen
(10, '550e8400-e29b-41d4-a716-446655440005', 3), -- truthfulqa_mc1
(11, '550e8400-e29b-41d4-a716-446655440005', 6); -- winogender

-- Insert Report Task Scores for Model Card Tasks
INSERT INTO model_card_task_scores (model_card_task_id, metric_id, score) VALUES
-- Phi-2 evaluation results (tasks 1-15)
-- BBQ scores (task 1)
(1, 1, 0.4654),   -- acc
(1, 2, 0.0941),   -- accuracy_amb
(1, 3, 0.8366),   -- accuracy_disamb
(1, 4, 0.2848),   -- amb_bias_score_Age
(1, 5, 0.0967),   -- disamb_bias_score_Age
(1, 6, 0.1417),   -- amb_bias_score_Gender_identity
(1, 7, 0.0508),   -- disamb_bias_score_Gender_identity
(1, 8, 0.0224),   -- amb_bias_score_Race_ethnicity
(1, 9, 0.0524),   -- disamb_bias_score_Race_ethnicity
-- Crows Pairs scores (task 2)
(2, 10, 0.6452), -- pct_stereotype
-- Toxigen scores (task 3)
(3, 13, 0.4585), -- acc
(3, 14, 0.4330), -- acc_norm
-- TruthfulQA scores (task 4)
(4, 11, 0.3084), -- acc
-- Winogender scores (task 5)
(5, 17, 0.6083), -- acc

-- Llama-3.1-8B-Instruct evaluation results (tasks 6-11)
-- BBQ scores (task 6)
(6, 1, 0.4879),   -- acc
(6, 2, 0.0746),   -- accuracy_amb
(6, 3, 0.9013),   -- accuracy_disamb
(6, 4, 0.4000),   -- amb_bias_score_Age
(6, 5, 0.0185),   -- disamb_bias_score_Age
(6, 6, 0.2384),   -- amb_bias_score_Gender_identity
(6, 7, 0.0099),   -- disamb_bias_score_Gender_identity
(6, 8, 0.0610),   -- amb_bias_score_Race_ethnicity
(6, 9, 0.0093),   -- disamb_bias_score_Race_ethnicity
-- Crows Pairs scores (task 7)
(7, 10, 0.6231), -- pct_stereotype
-- Ethics CM scores (task 8)
(8, 15, 0.6013), -- acc
-- Toxigen scores (task 9)
(9, 13, 0.5128), -- acc
(9, 14, 0.4309), -- acc_norm
-- TruthfulQA scores (task 10)
(10, 11, 0.3599), -- acc
-- Winogender scores (task 11)
(11, 17, 0.6167); -- acc 

-- Update sequence values to prevent conflicts with existing data
SELECT setval('model_card_task_SEQ', (SELECT MAX(id) FROM model_card_task) + 1);
