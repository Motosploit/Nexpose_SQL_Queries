# Returns counts of all Critical, High and Medium Vulnerabilities
# based on risk score, duplicates included
SELECT SUM(favf.vulnerability_instances) AS Critical
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv using (vulnerability_id)
JOIN dim_asset da using (asset_id)
WHERE dv.riskscore >= 900
UNION ALL
SELECT SUM(favf.vulnerability_instances) AS High
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv using (vulnerability_id)
JOIN dim_asset da using (asset_id)
WHERE dv.riskscore >= 700 AND dv.riskscore < 900
UNION ALL
SELECT SUM(favf.vulnerability_instances) AS Medium
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv using (vulnerability_id)
JOIN dim_asset da using (asset_id)
WHERE dv.riskscore >= 500 AND dv.riskscore < 700