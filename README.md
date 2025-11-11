# CxOne to GitLab Security Dashboard Transform Script

This bash script transforms CxOne container scanning results into a format compatible with GitLab's security dashboard.

## Overview

The script processes CxOne result files from multiple sources and extracts only the container scanning vulnerabilities, converting them to the GitLab security report format as defined in the [GitLab container scanning schema](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/container-scanning-report-format.json).

## Supported Input Formats

The script now supports **3 different CxOne result file formats**:

### 1. CxOne "All scanners results" API Format
- **Source**: CxOne REST API `/results` endpoint  
- **Example file**: `response_1762425373895.json`
- **Structure**: `{ "results": [...] }` with `type: "containers"` entries

### 2. CxOne CLI with "json" Option
- **Source**: CxOne CLI command: `cx scan create --scan-types containers --format json`
- **Example file**: `cx_result_jsonv1.json`  
- **Structure**: Similar to API format but includes `scanInformation` metadata

### 3. CxOne CLI with "jsonv2" Option  
- **Source**: CxOne CLI command: `cx scan create --scan-types containers --format jsonv2`
- **Example file**: `cx_result_jsonv2.json`
- **Structure**: Report format with `containerScanResults` section

The script automatically detects the input format and extracts container vulnerabilities accordingly.

## Prerequisites

- **bash** (compatible with macOS/Linux)
- **jq** - JSON processor (install with `brew install jq` on macOS or `apt-get install jq` on Ubuntu)

## Usage

```bash
./transform_cxone_to_gitlab.sh <input_cxone_results_file> <output_gitlab_format_file>
```

### Examples

```bash
# Transform API results
./transform_cxone_to_gitlab.sh response_1762425373895.json gitlab_container_report.json

# Transform CLI json results  
./transform_cxone_to_gitlab.sh cx_results.json gitlab_container_report.json

# Transform CLI jsonv2 results
./transform_cxone_to_gitlab.sh cx_results_v2.json gitlab_container_report.json
```

The script automatically detects the input format and processes it accordingly.

## Input Format Details

The script expects a CxOne result file in one of the supported formats. It will:

1. **Auto-detect the format** - Analyzes the JSON structure to identify the format type
2. **Extract only container results** - Filters results to container vulnerabilities only
3. **Ignore other scan types** - SAST, KICS, SCA results are filtered out  
4. **Transform data structure** - Maps CxOne fields to GitLab security dashboard format

### Format Detection Logic

| Format Type | Detection Method | Container Data Location |
|-------------|------------------|------------------------|
| **API Format** | Has `results[]` array without `scanInformation` | `results[] where type=="containers"` |  
| **CLI json** | Has `results[]` array with `scanInformation` | `results[] where type=="containers"` |
| **CLI jsonv2** | Has `reportType` and `containerScanResults` | `containerScanResults.images[].layers[].packages[].vulnerabilities[]` |

### Sample Input Structures

#### API Format (`response_1762425373895.json`)
```json
{
  "results": [{
    "type": "containers",
    "id": "CVE-2019-12900", 
    "severity": "CRITICAL",
    "description": "BZ2_decompress in decompress.c in bzip2...",
    "data": {
      "packageName": "libbz2",
      "packageVersion": "1.0.6-r6", 
      "imageName": "python",
      "imageTag": "alpine3.8"
    },
    "vulnerabilityDetails": {
      "cveName": "CVE-2019-12900",
      "cweId": "CWE-787",
      "cvssScore": 9.8
    }
  }]
}
```

#### CLI jsonv2 Format (`cx_result_jsonv2.json`)
```json
{
  "reportType": "Vulnerability Type",
  "containerScanResults": {
    "images": [{
      "name": "python:alpine3.8",
      "layers": [{
        "packages": [{
          "packageName": "libbz2",
          "version": "1.0.6-r6",
          "vulnerabilities": [{
            "cve": "CVE-2019-12900",
            "severity": "Critical",
            "cwe": "CWE-787"
          }]
        }]
      }]
    }]
  }
}
```

## Output Format

The script generates a GitLab security dashboard compatible JSON file with:

- **Metadata**: Scanner information, timestamps, scan status
- **Vulnerabilities**: Container-specific vulnerabilities with required GitLab fields
- **Compliance**: Follows GitLab container scanning report schema v15.2.3

### Sample GitLab Output Structure

```json
{
  "version": "15.2.3",
  "scan": {
    "analyzer": {
      "id": "cxone-container-scanner",
      "name": "CxOne Container Scanner",
      "version": "1.0.0",
      "vendor": {"name": "Checkmarx"}
    },
    "type": "container_scanning",
    "status": "success"
  },
  "vulnerabilities": [{
    "id": "CVE-2019-12900",
    "name": "CVE-2019-12900", 
    "description": "BZ2_decompress in decompress.c...",
    "severity": "Critical",
    "solution": "Upgrade libbz2 to a version that fixes CVE-2019-12900",
    "identifiers": [{
      "type": "cve",
      "name": "CVE-2019-12900",
      "value": "CVE-2019-12900",
      "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12900"
    }],
    "location": {
      "dependency": {
        "package": {"name": "libbz2"},
        "version": "1.0.6-r6"
      },
      "operating_system": "python:alpine3.8",
      "image": "python:alpine3.8"
    }
  }]
}
```

## Field Mappings

### API and CLI json Formats
| CxOne Field | GitLab Field | Transformation |
|-------------|--------------|----------------|
| `id` | `id` | Direct mapping |
| `vulnerabilityDetails.cveName` | `name` | Direct mapping |
| `description` | `description` | Direct mapping |
| `severity` | `severity` | CRITICAL→Critical, HIGH→High, MEDIUM→Medium, LOW→Low |
| `data.packageName` | `location.dependency.package.name` | Direct mapping |
| `data.packageVersion` | `location.dependency.version` | Direct mapping |
| `data.imageName:imageTag` | `location.image` & `location.operating_system` | Concatenated |
| `vulnerabilityDetails.cveName` | `identifiers[].value` | CVE identifier |

### CLI jsonv2 Format
| CxOne Field | GitLab Field | Transformation |
|-------------|--------------|----------------|
| `cve` | `id` | Direct mapping |
| `cve` | `name` | Direct mapping |
| Generated | `description` | "Vulnerability {cve} found in package {packageName}" |
| `severity` | `severity` | Critical→Critical, High→High, Medium→Medium, Low→Low |
| `packageName` | `location.dependency.package.name` | Direct mapping |
| `version` | `location.dependency.version` | Direct mapping |
| `image.name` | `location.image` & `location.operating_system` | Direct mapping |
| `cve` | `identifiers[].value` | CVE identifier |

## Script Features

### ✅ What it does:
- **Auto-detects input format** - Supports 3 different CxOne result file formats
- Extracts **only container scanning results** from CxOne response
- Transforms severity levels to GitLab format 
- Creates proper CVE identifiers with URLs
- Maps package and image information correctly
- Validates output JSON format
- Provides transformation statistics
- Shows sample vulnerability for verification

### ❌ What it doesn't do:
- Process SAST, KICS, or SCA results (by design)
- Add CVSS vectors (can be extended)
- Include CWE identifiers (can be extended)  
- Handle missing fields gracefully (will show null/empty)

## Format-Specific Notes

### CLI jsonv2 Format
- **Higher vulnerability count**: This format extracts vulnerabilities from nested package structure, often resulting in more detailed results
- **Generated descriptions**: Since the jsonv2 format doesn't include vulnerability descriptions, the script generates them from available data
- **Image name handling**: Parses image names that may include registry and tag information

## Output Statistics

The script provides a summary after successful transformation:

```
✅ Transformation completed successfully!
📊 Statistics:
   - Total vulnerabilities: 54
   - Critical: 6
   - High: 25  
   - Medium: 20
   - Low: 3

📄 Output file: gitlab_container_report.json
```

## Error Handling

The script includes comprehensive error checking:

- Validates input file exists
- Checks for required `jq` dependency  
- Validates output JSON format
- Provides clear error messages
- Returns appropriate exit codes

## Integration with GitLab

The generated report can be used directly with GitLab's security dashboard by:

1. **CI/CD Pipeline**: Upload as security report artifact
2. **Security Dashboard**: View vulnerabilities in GitLab UI
3. **Merge Request**: Show security changes in MR widget
4. **API Integration**: Consume via GitLab security APIs

### GitLab CI Example

```yaml
container_scan:
  stage: security
  script:
    - ./transform_cxone_to_gitlab.sh cxone_results.json gitlab_report.json
  artifacts:
    reports:
      container_scanning: gitlab_report.json
```

## Files

- `transform_cxone_to_gitlab.sh` - Main transformation script (supports 3 input formats)
- `README.md` - This documentation

## Testing

You can test the script with the provided sample files:

```bash
# Test with API format
./transform_cxone_to_gitlab.sh response_1762425373895.json test_api.json

# Test with CLI json format  
./transform_cxone_to_gitlab.sh cx_result_jsonv1.json test_cli_json.json

# Test with CLI jsonv2 format
./transform_cxone_to_gitlab.sh cx_result_jsonv2.json test_cli_jsonv2.json
```

Expected results:
- **API format**: ~54 container vulnerabilities
- **CLI json format**: ~356 container vulnerabilities  
- **CLI jsonv2 format**: ~702 container vulnerabilities (more detailed extraction)

## Contributing

To extend this script:

1. **Add CVSS vectors**: Enhance the jq transform to include `cvss_vectors` array
2. **Include CWE identifiers**: Map `vulnerabilityDetails.cweId` to identifiers
3. **Add more metadata**: Include scan options, messages, etc.
4. **Error handling**: Improve validation and error reporting

## License

This script is provided as-is for transforming CxOne results to GitLab format.
