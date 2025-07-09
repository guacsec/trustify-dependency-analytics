-- Create tables for Model Card entities

-- Model Card Report table
CREATE TABLE model_card_report (
    id UUID PRIMARY KEY,
    name VARCHAR(255),
    source VARCHAR(255),
    -- Embedded ModelCardConfig fields
    model_name VARCHAR(255),
    model_revision VARCHAR(255),
    model_sha VARCHAR(255),
    model_source VARCHAR(255),
    d_type VARCHAR(255),
    batch_size VARCHAR(255),
    batch_sizes integer[],
    lm_eval_version VARCHAR(255),
    transformers_version VARCHAR(255)
);

-- Task Definition table (parent entity)
CREATE TABLE task_definition (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    tags VARCHAR(255)[]
);

-- Task Metric table (child entity of task_definition)
CREATE TABLE task_metric (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255),
    task_definition_id BIGINT NOT NULL,
    higher_is_better BOOLEAN,
    categories VARCHAR(255)[],
    FOREIGN KEY (task_definition_id) REFERENCES task_definition(id) ON DELETE CASCADE
);

-- Threshold table
CREATE TABLE threshold (
    id BIGSERIAL PRIMARY KEY,
    task_metric_id BIGINT NOT NULL,
    lower FLOAT,
    upper FLOAT,
    name VARCHAR(255),
    category INTEGER,
    interpretation TEXT,
    FOREIGN KEY (task_metric_id) REFERENCES task_metric(id) ON DELETE CASCADE
);

-- Model Card Task table
CREATE TABLE model_card_task (
    id BIGSERIAL PRIMARY KEY,
    report_id UUID NOT NULL,
    task_id BIGINT NOT NULL,
    FOREIGN KEY (report_id) REFERENCES model_card_report(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES task_definition(id) ON DELETE CASCADE
);

-- Model Card Task Scores table
CREATE TABLE model_card_task_scores (
    model_card_task_id BIGINT NOT NULL,
    metric_id BIGINT NOT NULL,
    score FLOAT NOT NULL,
    PRIMARY KEY (model_card_task_id, metric_id),
    FOREIGN KEY (model_card_task_id) REFERENCES model_card_task(id) ON DELETE CASCADE,
    FOREIGN KEY (metric_id) REFERENCES task_metric(id) ON DELETE CASCADE
);

-- Create explicit sequences to match Hibernate's naming expectations
CREATE SEQUENCE model_card_task_SEQ START WITH 1 INCREMENT BY 50;
CREATE SEQUENCE task_definition_SEQ START WITH 1 INCREMENT BY 50;
CREATE SEQUENCE task_metric_SEQ START WITH 1 INCREMENT BY 50;
CREATE SEQUENCE threshold_SEQ START WITH 1 INCREMENT BY 50;

-- Update tables to use explicit sequences
ALTER TABLE model_card_task ALTER COLUMN id SET DEFAULT nextval('model_card_task_SEQ');
ALTER TABLE task_definition ALTER COLUMN id SET DEFAULT nextval('task_definition_SEQ');
ALTER TABLE task_metric ALTER COLUMN id SET DEFAULT nextval('task_metric_SEQ');
ALTER TABLE threshold ALTER COLUMN id SET DEFAULT nextval('threshold_SEQ');

-- Create indexes for better performance
CREATE INDEX idx_model_card_report_name ON model_card_report(name);
CREATE INDEX idx_model_card_report_source ON model_card_report(source);
CREATE INDEX idx_task_definition_name ON task_definition(name);
CREATE INDEX idx_task_metric_task_definition_id ON task_metric(task_definition_id);
CREATE INDEX idx_task_metric_name ON task_metric(name);
CREATE INDEX idx_threshold_task_metric_id ON threshold(task_metric_id);
CREATE INDEX idx_model_card_task_report_id ON model_card_task(report_id);
CREATE INDEX idx_model_card_task_scores_task_id ON model_card_task_scores(model_card_task_id);
CREATE INDEX idx_model_card_task_scores_metric_id ON model_card_task_scores(metric_id); 