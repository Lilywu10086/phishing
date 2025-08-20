# API Documentation

## Overview

The Phishing Website Detection System provides RESTful API interfaces that support programmatic calls to detection functions.

## Basic Information

- **Base URL**: `http://localhost:5000/api`
- **Authentication**: Some interfaces require user login
- **Data Format**: JSON
- **Character Encoding**: UTF-8

## API Interface List

### 1. Single URL Detection

**Interface**: `POST /api/detect`

**Description**: Detect the safety of a single URL

**Request Parameters**:
```json
{
    "url": "https://www.example.com"
}
```

**Response Example**:
```json
{
    "url": "https://www.example.com",
    "is_safe": true,
    "confidence_score": 0.85,
    "detected_at": "2024-01-15T10:30:00.000Z"
}
```

**Error Response**:
```json
{
    "error": "Please provide URL parameter"
}
```

### 2. Batch URL Detection

**Interface**: `POST /api/batch_detect`

**Description**: Batch detect the safety of multiple URLs

**Request Parameters**:
```json
{
    "urls": [
        "https://www.google.com",
        "https://www.example.com",
        "https://www.test.com"
    ]
}
```

**Response Example**:
```json
{
    "total": 3,
    "safe_count": 2,
    "unsafe_count": 1,
    "results": [
        {
            "url": "https://www.google.com",
            "is_safe": true,
            "confidence_score": 0.92,
            "detected_at": "2024-01-15T10:30:00.000Z"
        },
        {
            "url": "https://www.example.com",
            "is_safe": true,
            "confidence_score": 0.78,
            "detected_at": "2024-01-15T10:30:01.000Z"
        },
        {
            "url": "https://www.test.com",
            "is_safe": false,
            "confidence_score": 0.35,
            "detected_at": "2024-01-15T10:30:02.000Z"
        }
    ]
}
```

### 3. Get Detection History

**Interface**: `GET /api/history`

**Description**: Get user's detection history records (requires login)

**Request Parameters**:
- `page`: Page number (optional, default 1)
- `per_page`: Items per page (optional, default 20)

**Response Example**:
```json
{
    "history": [
        {
            "id": 1,
            "url": "https://www.example.com",
            "is_safe": true,
            "confidence_score": 0.85,
            "detected_at": "2024-01-15T10:30:00.000Z"
        }
    ],
    "total": 50,
    "pages": 3,
    "current_page": 1,
    "per_page": 20
}
```

### 4. Get Statistics

**Interface**: `GET /api/stats`

**Description**: Get user's detection statistics (requires login)

**Response Example**:
```json
{
    "total_detections": 100,
    "safe_count": 75,
    "unsafe_count": 25,
    "avg_confidence": 0.78,
    "safe_percentage": 75.0
}
```

## Usage Examples

### Python Example

```python
import requests
import json

# Base URL
base_url = "http://localhost:5000/api"

# Single detection
def detect_single(url):
    response = requests.post(f"{base_url}/detect", 
                           json={"url": url})
    return response.json()

# Batch detection
def detect_batch(urls):
    response = requests.post(f"{base_url}/batch_detect", 
                           json={"urls": urls})
    return response.json()

# Usage example
if __name__ == "__main__":
    # Single detection
    result = detect_single("https://www.google.com")
    print("Single detection result:", result)
    
    # Batch detection
    urls = [
        "https://www.google.com",
        "https://www.example.com",
        "https://www.test.com"
    ]
    results = detect_batch(urls)
    print("Batch detection result:", results)
```

### JavaScript Example

```javascript
// Single detection
async function detectSingle(url) {
    const response = await fetch('/api/detect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    });
    return await response.json();
}

// Batch detection
async function detectBatch(urls) {
    const response = await fetch('/api/batch_detect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ urls: urls })
    });
    return await response.json();
}

// Usage example
detectSingle('https://www.google.com')
    .then(result => console.log('Detection result:', result))
    .catch(error => console.error('Error:', error));
```

### cURL Example

```bash
# Single detection
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# Batch detection
curl -X POST http://localhost:5000/api/batch_detect \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://www.google.com", "https://www.example.com"]}'
```

## Error Code Description

| Status Code | Description |
|-------------|-------------|
| 200 | Request successful |
| 400 | Request parameter error |
| 401 | Unauthorized (requires login) |
| 500 | Server internal error |

## Notes

1. **URL Format**: Please ensure URLs include protocol (http:// or https://)
2. **Batch Detection Limit**: Maximum 50 URLs can be detected at once
3. **Detection Delay**: There is a 0.1 second delay between each URL during batch detection
4. **History Records**: Only logged-in users will have detection history saved
5. **Error Handling**: URLs that fail detection will return error information

## Performance Recommendations

1. **Concurrent Requests**: It's recommended to control the number of concurrent requests to avoid overwhelming the server
2. **Batch Detection**: For large numbers of URLs, it's recommended to use the batch detection interface
3. **Cache Results**: Clients can cache detection results to avoid repeated detection
4. **Error Retry**: For network errors, it's recommended to implement retry mechanisms

## Update Log

- **v1.0.0**: Initial version, supports single and batch detection
- **v1.1.0**: Added history records and statistics interfaces 