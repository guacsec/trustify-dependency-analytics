-- Migration to rename threshold.name to threshold.impact and update data to use enum values

-- First, add the new impact column
ALTER TABLE threshold ADD COLUMN impact VARCHAR(255);

-- Update the data to map the old name values to the new enum values using specific IDs
-- Crows Pairs English thresholds (pct_stereotype - lower is better)
UPDATE threshold SET impact = 'no_measurable' WHERE id = 1;  -- No measurable bias
UPDATE threshold SET impact = 'low' WHERE id = 2;       -- Mild bias
UPDATE threshold SET impact = 'moderate' WHERE id = 3;  -- Moderate to strong bias
UPDATE threshold SET impact = 'severe' WHERE id = 4;      -- Severe bias

-- BBQ bias score thresholds (amb_bias_score_Age - lower is better)
UPDATE threshold SET impact = 'very_low' WHERE id = 5;  -- Very low bias
UPDATE threshold SET impact = 'low' WHERE id = 6;       -- Low bias/ High fairness
UPDATE threshold SET impact = 'moderate' WHERE id = 7;  -- Low to moderate bias
UPDATE threshold SET impact = 'high' WHERE id = 8;      -- Moderate bias
UPDATE threshold SET impact = 'severe' WHERE id = 9;    -- Severe bias

-- TruthfulQA thresholds (acc - higher is better)
UPDATE threshold SET impact = 'very_low' WHERE id = 10; -- Excellent
UPDATE threshold SET impact = 'low' WHERE id = 11;      -- Good
UPDATE threshold SET impact = 'moderate' WHERE id = 12; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 13;     -- Low
UPDATE threshold SET impact = 'severe' WHERE id = 14;   -- Very low

-- TruthfulQA acc_norm thresholds (same as acc)
UPDATE threshold SET impact = 'very_low' WHERE id = 15; -- Excellent
UPDATE threshold SET impact = 'low' WHERE id = 16;      -- Good
UPDATE threshold SET impact = 'moderate' WHERE id = 17; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 18;     -- Low
UPDATE threshold SET impact = 'severe' WHERE id = 19;   -- Very low

-- Toxigen thresholds (acc - higher is better)
UPDATE threshold SET impact = 'very_low' WHERE id = 20; -- Very low
UPDATE threshold SET impact = 'low' WHERE id = 21;      -- Low
UPDATE threshold SET impact = 'moderate' WHERE id = 22; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 23;     -- High
UPDATE threshold SET impact = 'severe' WHERE id = 24;   -- Very high

-- Toxigen acc_norm thresholds (same as acc)
UPDATE threshold SET impact = 'very_low' WHERE id = 25; -- Very low
UPDATE threshold SET impact = 'low' WHERE id = 26;      -- Low
UPDATE threshold SET impact = 'moderate' WHERE id = 27; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 28;     -- High
UPDATE threshold SET impact = 'severe' WHERE id = 29;   -- Very high

-- Ethics CM thresholds (acc - higher is better)
UPDATE threshold SET impact = 'very_low' WHERE id = 30; -- Excellent
UPDATE threshold SET impact = 'low' WHERE id = 31;      -- Good
UPDATE threshold SET impact = 'moderate' WHERE id = 32; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 33;     -- Low
UPDATE threshold SET impact = 'severe' WHERE id = 34;   -- Very low

-- Ethics CM acc_norm thresholds (same as acc)
UPDATE threshold SET impact = 'very_low' WHERE id = 35; -- Excellent
UPDATE threshold SET impact = 'low' WHERE id = 36;      -- Good
UPDATE threshold SET impact = 'moderate' WHERE id = 37; -- Moderate
UPDATE threshold SET impact = 'high' WHERE id = 38;     -- Low
UPDATE threshold SET impact = 'severe' WHERE id = 39;   -- Very low

-- Winogender thresholds (acc and acc_norm - higher is better)
UPDATE threshold SET impact = 'moderate' WHERE id = 40; -- Moderate
UPDATE threshold SET impact = 'moderate' WHERE id = 41; -- Moderate

-- Drop the old name column
ALTER TABLE threshold DROP COLUMN name;
