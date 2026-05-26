-- VENDOR RISK INTELLIGENCE

-- SECTION 1: SCHEMA SETUP
CREATE TABLE vendors (
    vendor_id VARCHAR(10) PRIMARY KEY,
    vendor_name VARCHAR(100) NOT NULL,
    category VARCHAR(60), country VARCHAR(60), onboarding_date DATE,
    contract_value_usd DECIMAL(12,2), data_access_level VARCHAR(10), 
    soc2_certified INTEGER DEFAULT 0, gdpr_compliant INTEGER DEFAULT 0, iso27001_certified INTEGER DEFAULT 0,
    financial_health_score INTEGER, incident_history_count INTEGER DEFAULT 0,
    dependency_flag INTEGER DEFAULT 0, risk_tier VARCHAR(10)
);

CREATE TABLE risk_scores (
    score_id VARCHAR(10) PRIMARY KEY, vendor_id VARCHAR(10), assessment_date DATE,
    compliance_score DECIMAL(5,2), financial_score DECIMAL(5,2), security_score DECIMAL(5,2),
    operational_score DECIMAL(5,2), reputational_score DECIMAL(5,2), weighted_risk_score DECIMAL(5,2),
    assessor VARCHAR(80), FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);

CREATE TABLE incidents (
    incident_id VARCHAR(10) PRIMARY KEY, vendor_id VARCHAR(10), incident_date DATE,
    incident_type VARCHAR(60), severity VARCHAR(10), records_exposed INTEGER DEFAULT 0,
    estimated_cost_usd DECIMAL(12,2), resolution_days INTEGER, resolved INTEGER DEFAULT 0,
    root_cause VARCHAR(200), FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);


-- SECTION 2: AUTOMATED RISK TIER SCORING
-- 2a. Composite Intake Score per Vendor 
WITH weighted AS (
    SELECT vendor_id, vendor_name, category, data_access_level,
        ROUND((
            (soc2_certified * 33 + gdpr_compliant * 33 + iso27001_certified * 34) * 0.35 +
            (financial_health_score * 0.20) +
            (CASE WHEN (100 - incident_history_count * 10) < 0 THEN 0 ELSE (100 - incident_history_count * 10) END * 0.30) +
            7.5 -- 50 * 0.15 baseline
        ) * CASE data_access_level WHEN 'HIGH' THEN 0.85 WHEN 'MEDIUM' THEN 0.95 ELSE 1.00 END, 2) AS composite_score
    FROM vendors
)
SELECT *, CASE WHEN composite_score >= 80 THEN 'LOW' WHEN composite_score >= 60 THEN 'MEDIUM' 
               WHEN composite_score >= 40 THEN 'HIGH' ELSE 'CRITICAL' END AS assigned_risk_tier
FROM weighted ORDER BY composite_score;

-- 2b. Risk Tier Distribution Summary
SELECT risk_tier, COUNT(*) AS vendor_count, SUM(contract_value_usd) AS total_spend,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM vendors), 1) AS pct_vendors,
    ROUND(SUM(contract_value_usd) * 100.0 / (SELECT SUM(contract_value_usd) FROM vendors), 1) AS pct_spend
FROM vendors GROUP BY risk_tier
ORDER BY CHARINDEX(risk_tier, 'CRITICAL,HIGH,MEDIUM,LOW'); -- Or INSTR() depending on your SQL engine


-- SECTION 3: CONCENTRATION RISK & DEPENDENCY
-- 3a. Spend Concentration by Category
SELECT category, COUNT(*) AS vendor_count, SUM(contract_value_usd) AS category_spend,
    ROUND(SUM(contract_value_usd) * 100.0 / (SELECT SUM(contract_value_usd) FROM vendors), 2) AS spend_share_pct,
    CASE WHEN SUM(contract_value_usd) * 100.0 / (SELECT SUM(contract_value_usd) FROM vendors) > 20 THEN 'HIGH CONCENTRATION'
         WHEN SUM(contract_value_usd) * 100.0 / (SELECT SUM(contract_value_usd) FROM vendors) > 10 THEN 'MODERATE CONCENTRATION'
         ELSE 'DIVERSIFIED' END AS concentration_flag
FROM vendors GROUP BY category ORDER BY spend_share_pct DESC;

-- 3b. Single-Vendor Dependency Detection (Removed CTE via Window Count)
SELECT category, vendors_in_category, category_spend,
    CASE WHEN vendors_in_category = 1 THEN vendor_name END AS sole_vendor,
    CASE WHEN vendors_in_category = 1 THEN risk_tier END AS sole_vendor_tier,
    CASE WHEN vendors_in_category = 1 THEN 'SINGLE-VENDOR DEPENDENCY' ELSE 'OK' END AS dependency_status
FROM (
    SELECT category, vendor_name, risk_tier, contract_value_usd,
        COUNT(*) OVER(PARTITION BY category) AS vendors_in_category,
        SUM(contract_value_usd) OVER(PARTITION BY category) AS category_spend,
        ROW_NUMBER() OVER(PARTITION BY category ORDER BY vendor_id) AS rn
    FROM vendors
) t WHERE rn = 1 OR vendors_in_category = 1
ORDER BY vendors_in_category, category_spend DESC;

-- 3c. Vendor Spend Rank within Category (Window Functions)
SELECT vendor_id, vendor_name, category, contract_value_usd, dependency_flag, risk_tier,
    RANK() OVER (PARTITION BY category ORDER BY contract_value_usd DESC) AS spend_rank_in_category,
    SUM(contract_value_usd) OVER (PARTITION BY category ORDER BY contract_value_usd DESC ROWS UNBOUNDED PRECEDING) AS cumulative_spend
FROM vendors ORDER BY category, contract_value_usd DESC;


-- SECTION 4: DATA BREACH IMPACT ASSESSMENT
-- 4a. Incident Cost Rollup per Vendor 
SELECT i.vendor_id, v.vendor_name, v.risk_tier, COUNT(i.incident_id) AS total_incidents,
    SUM(i.records_exposed) AS total_records_exposed, SUM(i.estimated_cost_usd) AS total_incident_cost,
    ROUND(AVG(COALESCE(i.resolution_days, 0)), 1) AS avg_resolution_days, SUM(CASE WHEN i.resolved = 0 THEN 1 ELSE 0 END) AS open_incidents,
    MAX(i.severity) AS worst_severity, -- Keeps original logic; map to weights if ordering alphabetically fails your engine
    SUM(SUM(i.estimated_cost_usd)) OVER (ORDER BY SUM(i.estimated_cost_usd) DESC ROWS UNBOUNDED PRECEDING) AS cumulative_breach_cost
FROM incidents i JOIN vendors v ON i.vendor_id = v.vendor_id
GROUP BY i.vendor_id, v.vendor_name, v.risk_tier
ORDER BY total_incident_cost DESC;

-- 4b. Severity Heatmap (Category x Severity)
SELECT v.category, i.severity, COUNT(i.incident_id) AS incident_count,
    SUM(i.estimated_cost_usd) AS total_cost, SUM(i.records_exposed) AS total_records_exposed
FROM incidents i JOIN vendors v ON i.vendor_id = v.vendor_id
GROUP BY v.category, i.severity
ORDER BY v.category, CHARINDEX(i.severity, 'CRITICAL,HIGH,MEDIUM,LOW');

-- 4c. Open & Critical Incident Watchlist
SELECT i.incident_id, v.vendor_name, v.risk_tier, i.incident_date, i.incident_type, i.severity, i.records_exposed, i.estimated_cost_usd,
    COALESCE(i.resolution_days, 0) AS resolution_days, i.root_cause,
    ROUND((i.estimated_cost_usd / 10000.0) + (COALESCE(i.resolution_days, 0) * 0.5), 1) AS urgency_score
FROM incidents i JOIN vendors v ON i.vendor_id = v.vendor_id
WHERE i.resolved = 0 OR i.severity IN ('CRITICAL', 'HIGH')
ORDER BY urgency_score DESC;


-- SECTION 5: COMPLIANCE TRACKING
-- 5a. Certification Gap Matrix
SELECT vendor_id, vendor_name, risk_tier, data_access_level, soc2_certified, gdrp_compliant, iso27001_certified,
    (soc2_certified + gdpr_compliant + iso27001_certified) AS certs_held,
    CASE WHEN data_access_level = 'HIGH' AND (soc2_certified + gdpr_compliant + iso27001_certified) < 3 THEN 'COMPLIANCE GAP - IMMEDIATE REVIEW'
         WHEN data_access_level = 'MEDIUM' AND (soc2_certified + gdpr_compliant + iso27001_certified) < 2 THEN 'PARTIAL COMPLIANCE - REVIEW RECOMMENDED'
         ELSE 'COMPLIANT' END AS compliance_status
FROM vendors
ORDER BY CHARINDEX(data_access_level, 'HIGH,MEDIUM,LOW'), certs_held;

-- 5b. Compliance Gaps by Country
SELECT v.country, COUNT(*) AS vendor_count,
    SUM(1 - v.gdpr_compliant) AS gdpr_gaps, SUM(1 - v.soc2_certified) AS soc2_gaps, SUM(1 - v.iso27001_certified) AS iso_gaps,
    ROUND(AVG(rs.weighted_risk_score), 1) AS avg_risk_score
FROM vendors v LEFT JOIN risk_scores rs ON v.vendor_id = rs.vendor_id
GROUP BY v.country 
ORDER BY (gdpr_gaps + soc2_gaps + iso_gaps) DESC;


-- SECTION 6: EXECUTIVE KPI SUMMARY

SELECT * FROM (
    SELECT COUNT(*) AS total_vendors, SUM(contract_value_usd) AS total_portfolio_spend,
        ROUND(AVG(financial_health_score), 1) AS avg_financial_health,
        SUM(CASE WHEN risk_tier = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_vendors,
        SUM(CASE WHEN risk_tier = 'HIGH' THEN 1 ELSE 0 END) AS high_risk_vendors,
        SUM(CASE WHEN dependency_flag = 1 THEN 1 ELSE 0 END) AS single_dep_vendors,
        SUM(CASE WHEN data_access_level = 'HIGH' AND soc2_certified = 0 THEN 1 ELSE 0 END) AS high_access_no_soc2
    FROM vendors
) v CROSS JOIN (
    SELECT COUNT(*) AS total_incidents, SUM(records_exposed) AS total_records_breached,
        SUM(estimated_cost_usd) AS total_breach_cost, SUM(CASE WHEN resolved = 0 THEN 1 ELSE 0 END) AS open_incidents
    FROM incidents
) i;
