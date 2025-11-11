#!/bin/bash

# Script to transform CxOne container results file into GitLab security dashboard compatible format
# Supports 3 input formats:
# 1. CxOne "All scanners results" API format
# 2. CxOne CLI with "json" option  
# 3. CxOne CLI with "jsonv2" option
# Usage: ./transform_cxone_to_gitlab.sh <input_file> <output_file>

set -euo pipefail

# Check if the correct number of arguments is provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_cxone_results_file> <output_gitlab_format_file>"
    echo "Example: $0 response_1762425373895.json gitlab_container_report.json"
    echo ""
    echo "Supported input formats:"
    echo "  1. CxOne 'All scanners results' API format"
    echo "  2. CxOne CLI with 'json' option"
    echo "  3. CxOne CLI with 'jsonv2' option"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist."
    exit 1
fi

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq to use this script."
    exit 1
fi

echo "Transforming CxOne results to GitLab security dashboard format..."
echo "Input file: $INPUT_FILE"
echo "Output file: $OUTPUT_FILE"

# Generate timestamp
TIMESTAMP=$(date +"%Y-%m-%dT%H:%M:%S")

# Function to detect input format and extract container vulnerabilities
detect_and_extract_containers() {
    local input_file="$1"
    local temp_containers="$2"
    
    echo "Step 1: Detecting input format and extracting container vulnerabilities..."
    
    # Check if it's format type 3 (CLI jsonv2) - has reportType and containerScanResults
    if jq -e '.reportType and .containerScanResults' "$input_file" >/dev/null 2>&1; then
        echo "Detected: CxOne CLI 'jsonv2' format"
        
        # Extract container vulnerabilities from containerScanResults structure
        jq '
        [
          .containerScanResults.images[] as $image |
          .containerScanResults.images[] | .layers[] | .packages[] as $package |
          $package.vulnerabilities[] |
          {
            "id": .cve,
            "severity": .severity,
            "description": ("Vulnerability " + .cve + " found in package " + $package.packageName),
            "data": {
              "packageName": $package.packageName,
              "packageVersion": $package.version,
              "imageName": ($image.name | split(":")[0]),
              "imageTag": ($image.name | split(":")[1] // "latest")
            },
            "vulnerabilityDetails": {
              "cveName": .cve,
              "cweId": .cwe
            }
          }
        ]' "$input_file" | jq '.[]' > "$temp_containers"
        
        local container_count=$(jq -s '. | length' "$temp_containers")
        echo "Found $container_count container vulnerabilities"
        return
    fi
    
    # Check if it's format type 1 or 2 - both have results array
    if jq -e '.results' "$input_file" >/dev/null 2>&1; then
        # Try to find container results
        local container_count=$(jq '[.results[] | select(.type == "containers")] | length' "$input_file")
        
        if [ "$container_count" -gt 0 ]; then
            if jq -e '.scanInformation' "$input_file" >/dev/null 2>&1; then
                echo "Detected: CxOne CLI 'json' format"
            else
                echo "Detected: CxOne 'All scanners results' API format"
            fi
            
            # Extract container vulnerabilities
            jq '.results[] | select(.type == "containers")' "$input_file" > "$temp_containers"
            echo "Found $container_count container vulnerabilities"
        else
            echo "No container vulnerabilities found in results array"
            echo "[]" > "$temp_containers"
        fi
    else
        echo "Error: Unrecognized input format. Expected CxOne results file with 'results' array or 'containerScanResults'."
        exit 1
    fi
}

# Create temporary files
TEMP_CONTAINERS=$(mktemp)
TEMP_VULNS=$(mktemp)

# Detect format and extract container vulnerabilities
detect_and_extract_containers "$INPUT_FILE" "$TEMP_CONTAINERS"

# Step 2: Transform each vulnerability to GitLab format
echo "Step 2: Transforming vulnerabilities to GitLab format..."

cat > transform_vuln.jq << 'EOF'
{
  "id": .id,
  "name": (.vulnerabilityDetails.cveName // .id),
  "description": .description,
  "severity": (
    if .severity == "CRITICAL" or .severity == "Critical" then "Critical"
    elif .severity == "HIGH" or .severity == "High" then "High" 
    elif .severity == "MEDIUM" or .severity == "Medium" then "Medium"
    elif .severity == "LOW" or .severity == "Low" then "Low"
    else "Unknown" 
    end
  ),
  "solution": ("Upgrade " + (.data.packageName // "package") + " to a version that fixes " + (.vulnerabilityDetails.cveName // .id)),
  "identifiers": [
    {
      "type": "cve",
      "name": (.vulnerabilityDetails.cveName // .id),
      "value": (.vulnerabilityDetails.cveName // .id),
      "url": ("https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + (.vulnerabilityDetails.cveName // .id))
    }
  ],
  "links": [
    {
      "name": (.vulnerabilityDetails.cveName // .id),
      "url": ("https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + (.vulnerabilityDetails.cveName // .id))
    }
  ],
  "location": {
    "dependency": {
      "package": {
        "name": (.data.packageName // "unknown")
      },
      "version": (.data.packageVersion // "unknown")
    },
    "operating_system": ((.data.imageName // "unknown") + ":" + (.data.imageTag // "unknown")),
    "image": ((.data.imageName // "unknown") + ":" + (.data.imageTag // "unknown"))
  }
}
EOF

# Transform vulnerabilities using the jq script
jq -f transform_vuln.jq "$TEMP_CONTAINERS" | jq -s . > "$TEMP_VULNS"

# Step 3: Create the final GitLab report
echo "Step 3: Creating GitLab security report..."
cat > "$OUTPUT_FILE" << EOF
{
  "version": "15.2.3",
  "scan": {
    "analyzer": {
      "id": "cxone-container-scanner",
      "name": "CxOne Container Scanner",
      "version": "1.0.0",
      "vendor": {
        "name": "Checkmarx"
      }
    },
    "scanner": {
      "id": "cxone-container-scanner",
      "name": "CxOne Container Scanner", 
      "version": "1.0.0",
      "vendor": {
        "name": "Checkmarx"
      }
    },
    "type": "container_scanning",
    "start_time": "$TIMESTAMP",
    "end_time": "$TIMESTAMP",
    "status": "success"
  },
  "vulnerabilities": $(cat "$TEMP_VULNS")
}
EOF

# Clean up temporary files
rm -f "$TEMP_CONTAINERS" "$TEMP_VULNS" transform_vuln.jq

# Validate the generated JSON
if jq empty "$OUTPUT_FILE" 2>/dev/null; then
    echo "✅ Transformation completed successfully!"
    echo "📊 Statistics:"
    
    # Count vulnerabilities by severity
    CRITICAL_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "Critical")] | length' "$OUTPUT_FILE")
    HIGH_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "High")] | length' "$OUTPUT_FILE")
    MEDIUM_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "Medium")] | length' "$OUTPUT_FILE")
    LOW_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "Low")] | length' "$OUTPUT_FILE")
    TOTAL_COUNT=$(jq '.vulnerabilities | length' "$OUTPUT_FILE")
    
    echo "   - Total vulnerabilities: $TOTAL_COUNT"
    echo "   - Critical: $CRITICAL_COUNT"
    echo "   - High: $HIGH_COUNT"
    echo "   - Medium: $MEDIUM_COUNT"
    echo "   - Low: $LOW_COUNT"
    echo ""
    echo "📄 Output file: $OUTPUT_FILE"
    
    # Show a sample of the first vulnerability if any exist
    if [ "$TOTAL_COUNT" -gt 0 ]; then
        echo ""
        echo "📋 Sample vulnerability (first one):"
        jq '.vulnerabilities[0]' "$OUTPUT_FILE"
    else
        echo ""
        echo "⚠️  No container vulnerabilities found in the input file."
        echo "   This may be expected if:"
        echo "   - The scan found no container vulnerabilities"
        echo "   - The input file contains only SAST/SCA/IaC results"
        echo "   - The input format is not supported for container extraction"
    fi
else
    echo "❌ Error: Generated JSON is invalid!"
    jq . "$OUTPUT_FILE" 2>&1 | head -10
    exit 1
fi