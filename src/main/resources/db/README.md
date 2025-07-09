# Database Migration Scripts

This directory contains SQL scripts for setting up the Model Card database schema and sample data.

## Files

- `V1__create_model_card_tables.sql` - Creates the database tables for Model Card entities
- `V2__insert_sample_data.sql` - Inserts sample data for testing and development

## Table Structure

### model_card_report
Main table containing model evaluation reports with embedded configuration data.

### task_definition  
Defines evaluation tasks with their metrics and categories.

### threshold
Defines performance thresholds for each task definition.

### model_card_task
Links tasks to specific model reports.

### model_card_task_scores
Stores the actual scores for each task (Map<String, Float> relationship).

## Usage

### Flyway Migration (Current Setup)
This project is configured to use Flyway for database migrations. The migration scripts will be automatically executed when the application starts.

Configuration in `application.properties`:
```properties
quarkus.flyway.migrate-at-start=true
quarkus.flyway.locations=classpath:db/migration
quarkus.flyway.baseline-on-migrate=true
quarkus.flyway.baseline-version=0
quarkus.hibernate-orm.database.generation=none
```

### Manual Execution (Alternative)
You can also run the scripts manually in your database:

```sql
-- First create the tables
migration/V1__create_model_card_tables.sql

-- Then insert sample data
examples/V2__insert_sample_data.sql
```

## Sample Data

The sample data includes:
- 3 model evaluation reports (Llama-3.1-8B, GPT-4, Claude-3)
- 5 task definitions (MMLU, ARC, HellaSWAG, TruthfulQA, GSM8K)
- Performance thresholds for each task
- Sample scores for each model-task combination

## Testing the Data

You can test the data by querying:

```sql
-- Get all model reports
SELECT * FROM model_card_report;

-- Get tasks for a specific report
SELECT mct.alias, mcrs.score_name, mcrs.score_value 
FROM model_card_task mct
JOIN model_card_task_scores mcrs ON mct.id = mcrs.model_card_task_id
WHERE mct.report_id = '550e8400-e29b-41d4-a716-446655440001';
``` 