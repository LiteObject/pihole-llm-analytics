# Pi-hole LLM Analytics

A Python script that fetches DNS query logs from Pi-hole v6 and analyzes them using a local Ollama LLM to provide security insights and network behavior analysis.

## Features

- **Pi-hole Integration**: Authenticates to Pi-hole v6 API and fetches DNS query logs
- **LLM Analysis**: Uses local Ollama server to analyze network traffic patterns
- **Security Insights**: Identifies suspicious domains, traffic trends, and provides actionable recommendations
- **Configurable**: Customizable query count, LLM model, and analysis parameters

## Prerequisites

- Pi-hole v6 with API access
- [Ollama](https://ollama.ai/) installed and running locally
- Python 3.7+

## Installation

1. Clone the repository:
```bash
git clone https://github.com/LiteObject/pihole-llm-analytics.git
cd pihole-llm-analytics
```

2. Create a virtual environment:
```bash
python -m venv .venv
```

3. Activate the virtual environment:
```bash
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root with the following variables:

```env
# Pi-hole Configuration (Required)
PIHOLE_HOST=127.0.0.1
PIHOLE_PORT=80
PIHOLE_PASSWORD=your_pihole_admin_password

# Ollama Configuration (Optional)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=gpt-oss:latest

# Analysis Settings (Optional)
LOG_COUNT=100
MAX_PROMPT_CHARS=18000
```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `PIHOLE_HOST` | `127.0.0.1` | Pi-hole server IP address |
| `PIHOLE_PORT` | `80` | Pi-hole web interface port |
| `PIHOLE_PASSWORD` | *Required* | Pi-hole admin password |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `gpt-oss:latest` | Ollama model to use for analysis |
| `LOG_COUNT` | `100` | Number of recent DNS queries to analyze |
| `MAX_PROMPT_CHARS` | `18000` | Maximum characters in LLM prompt |

## Usage

1. Ensure Pi-hole is running and accessible
2. Start Ollama with your preferred model:
```bash
ollama pull gpt-oss:latest
ollama serve
```

3. Run the analysis:
```bash
python app.py
```

## Sample Output

The script provides JSON-formatted analysis including:

- **Summary**: 3-5 bullet points of notable trends
- **Top Clients**: Most active devices and their blocked query counts
- **Top Domains**: Most frequently queried domains
- **Suspicious Patterns**: Potentially malicious domains or behaviors
- **Recommended Actions**: Practical next steps for network security

```json
{
  "summary": [
    "High volume of DNS queries from 192.168.1.100 (45% of total traffic)",
    "15% of queries blocked by Pi-hole filters",
    "Significant IoT device activity detected"
  ],
  "top_clients": [
    {"client": "192.168.1.100", "total": 450, "blocked": 67},
    {"client": "192.168.1.101", "total": 234, "blocked": 12}
  ],
  "top_domains": [
    {"domain": "google.com", "count": 89},
    {"domain": "cloudflare.com", "count": 67}
  ],
  "suspicious": [
    "Multiple queries to recently registered domains",
    "Unusual subdomain patterns in crypto-mining domains"
  ],
  "actions": [
    "Investigate high-volume client 192.168.1.100",
    "Review and update blocklists for crypto-mining domains"
  ]
}
```

## Dependencies

- `python-dotenv`: Environment variable management
- `requests`: HTTP client for API calls

## Error Handling

The script includes robust error handling for:
- Pi-hole authentication failures
- Network connectivity issues
- Ollama server unavailability
- Invalid API responses

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Troubleshooting

### Common Issues

**Authentication Error**: Verify your `PIHOLE_PASSWORD` in the `.env` file matches your Pi-hole admin password.

**Ollama Connection Error**: Ensure Ollama is running and accessible at the configured URL:
```bash
curl http://localhost:11434/api/tags
```

**No Logs Returned**: Check that your Pi-hole has recent DNS query data and the API endpoint is accessible.

**Model Not Found**: Pull the required model in Ollama:
```bash
ollama pull gpt-oss:latest
```

## Security Notes

- Store your Pi-hole password securely in the `.env` file
- Ensure `.env` is added to `.gitignore` to prevent credential exposure
- Run Ollama locally to keep DNS log data private
- Consider network segmentation for enhanced security

## Roadmap

- [ ] Support for multiple Pi-hole instances
- [ ] Historical trend analysis
- [ ] Custom alert rules
- [ ] Web dashboard interface
- [ ] Export reports to various formats
