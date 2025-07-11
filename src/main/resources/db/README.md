# Database Migration Scripts

This directory contains SQL scripts for setting up the Model Card database schema and sample data.

## Files

- `V1__create_model_card_tables.sql` - Creates the database tables for Model Card entities
- `V2__insert_base_data.sql` - Inserts initial configuration data for Tasks and Thresholds
- `V3__insert_report_data.sql` - Inserts data from the available reports existing at the moment 

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

-- Then insert other data
examples/VX__insert_XXXX_data.sql
```
