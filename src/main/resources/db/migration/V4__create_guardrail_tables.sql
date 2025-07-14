-- Create tables for Guardrail entity

-- Guardrail table
CREATE TABLE guardrail (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    scope VARCHAR(255),
    external_references VARCHAR(255)[],
    metadata_keys VARCHAR(255)[],
    instructions TEXT
);

-- Guardrail Metrics join table
CREATE TABLE guardrail_metrics (
    guardrail_id BIGINT NOT NULL,
    task_metric_id BIGINT NOT NULL,
    PRIMARY KEY (guardrail_id, task_metric_id),
    FOREIGN KEY (guardrail_id) REFERENCES guardrail(id) ON DELETE CASCADE,
    FOREIGN KEY (task_metric_id) REFERENCES task_metric(id) ON DELETE CASCADE
);

-- Create explicit sequence to match Hibernate's naming expectations
CREATE SEQUENCE guardrail_SEQ START WITH 1 INCREMENT BY 50;

-- Update table to use explicit sequence
ALTER TABLE guardrail ALTER COLUMN id SET DEFAULT nextval('guardrail_SEQ');

-- Create indexes for better performance
CREATE INDEX idx_guardrail_name ON guardrail(name);
CREATE INDEX idx_guardrail_scope ON guardrail(scope);
CREATE INDEX idx_guardrail_metrics_guardrail_id ON guardrail_metrics(guardrail_id);
CREATE INDEX idx_guardrail_metrics_task_metric_id ON guardrail_metrics(task_metric_id); 