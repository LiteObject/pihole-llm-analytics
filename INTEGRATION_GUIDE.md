# Pi-hole LLM Analytics - Integration Guide

## New Integrated Architecture

The original [`app.py`](app.py ) functionality has been successfully integrated into the main project architecture with the following improvements:

### ✅ What's New

1. **LLM Analyzer Module** (`pihole_analytics/analytics/llm_analyzer.py`)
   - Structured LLM analysis with proper error handling
   - Configurable Ollama integration
   - JSON response parsing and validation
   - Connection testing and model management

2. **Integrated Main Application** (`pihole_analytics/main.py`)
   - Updated to use the new LLM analyzer
   - Graceful fallback when LLM is unavailable
   - Enhanced error handling and logging

3. **New Scripts**
   - `integrated_analysis.py` - Replacement for [`app.py`](app.py ) with better structure
   - `example_integrated.py` - Demonstrates the new functionality

### 🚀 Quick Start

#### 1. Environment Setup
Create a `.env` file with your configuration:
```bash
# Pi-hole Configuration
PIHOLE_HOST=192.168.7.99
PIHOLE_PORT=8080
PIHOLE_PASSWORD=your_actual_password

# LLM Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=gpt-oss:latest
OLLAMA_TIMEOUT=120
OLLAMA_TEMPERATURE=0.2
MAX_PROMPT_CHARS=18000
```

#### 2. Using the Integrated Analysis Script
```bash
# Basic analysis (replaces old app.py)
python integrated_analysis.py

# Analyze more queries with JSON output
python integrated_analysis.py --count 500 --output json

# Test connections only
python integrated_analysis.py --test-connection

# Use different model
python integrated_analysis.py --model llama3.2:latest
```

#### 3. Using the Full CLI
```bash
# Comprehensive analysis
python -m pihole_analytics analyze --count 1000

# Generate security report
python -m pihole_analytics report --type security

# Check system status
python -m pihole_analytics status
```

#### 4. Programmatic Usage
```python
from pihole_analytics.core.pihole_client import PiholeClient
from pihole_analytics.analytics.llm_analyzer import LLMAnalyzer, LLMConfig
from pihole_analytics.utils.config import PiholeConfig

# Configure clients
pihole_config = PiholeConfig(host="192.168.7.99", port=8080, password="your_password")
llm_config = LLMConfig.from_env()

# Initialize analyzers
pihole_client = PiholeClient(pihole_config)
llm_analyzer = LLMAnalyzer(llm_config)

# Fetch and analyze
with pihole_client:
    queries = pihole_client.fetch_queries(100)
    analysis = llm_analyzer.analyze_queries(queries)
    print(f"Risk level: {analysis.threat_summary.get('risk_level')}")
```

### 📊 Analysis Features

The integrated LLM analyzer provides:

- **Traffic Analysis**: Query patterns, top domains/clients, block rates
- **Security Insights**: Suspicious domains, anomaly detection, threat assessment
- **Risk Assessment**: Overall risk scoring with explanations
- **Structured Output**: JSON format with standardized schema
- **Fallback Support**: Graceful degradation when LLM is unavailable

### 🔧 Configuration Options

#### LLM Configuration
```python
llm_config = LLMConfig(
    url="http://localhost:11434",      # Ollama server URL
    model="gpt-oss:latest",            # Model name
    timeout=120,                       # Request timeout
    max_prompt_chars=18000,            # Prompt size limit
    temperature=0.2,                   # Response creativity
    max_tokens=512                     # Response length limit
)
```

#### Analysis Customization
```python
# Custom analysis instructions
custom_instructions = """
Analyze the DNS logs focusing on:
1. Gaming traffic patterns
2. Streaming service usage
3. Potential bandwidth issues
Return analysis in the standard JSON format.
"""

analysis = llm_analyzer.analyze_queries(queries, custom_instructions)
```

### 🛡️ Error Handling

The integrated system handles various failure scenarios:

1. **Pi-hole API Restrictions**: Graceful fallback to available data
2. **LLM Service Unavailable**: Continues with basic analysis
3. **Network Issues**: Proper timeout and retry mechanisms
4. **Invalid Responses**: JSON parsing with fallback formatting

### 🔍 Migration from [`app.py`](app.py )

If you were using the original [`app.py`](app.py ):

| Old [`app.py`](app.py ) | New Integrated Approach |
|---------|-------------------------|
| `python app.py` | `python integrated_analysis.py` |
| Direct function calls | Structured classes with error handling |
| Basic error handling | Comprehensive logging and fallbacks |
| Single output format | Multiple output formats (JSON, text) |
| Environment variables only | Environment + programmatic configuration |

### 🧪 Testing

```bash
# Test all connections
python integrated_analysis.py --test-connection

# Run example with verbose logging
python example_integrated.py

# Test specific functionality
python -m pihole_analytics status
```

### 📈 Performance Considerations

- **Query Limits**: Start with 100-500 queries for testing
- **Prompt Size**: Automatically truncated to fit LLM context
- **Timeouts**: Configurable for different network conditions
- **Memory Usage**: Efficient streaming and processing

### 🤝 Compatibility

- **Pi-hole v5.x**: Full compatibility
- **Pi-hole v6.x**: Enhanced support with multiple auth methods
- **Ollama**: Any compatible model (tested with gpt-oss, llama3.2)
- **Python**: 3.8+ required

### 📝 Next Steps

1. **Remove old [`app.py`](app.py )**: Once satisfied with the integrated version
2. **Customize analysis**: Modify prompts for specific use cases
3. **Extend functionality**: Add custom analyzers and reports
4. **Monitor performance**: Use logging to track analysis quality

For detailed API documentation, see the individual module docstrings.
