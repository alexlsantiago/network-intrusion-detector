# Network Intrusion Detector

A modern, streamlined network intrusion detection system built with Streamlit. This application provides real-time network monitoring, threat analysis, and security insights through an intuitive web interface.

## Features

- **Real-time Monitoring**: Live network traffic analysis and threat detection
- **Threat Intelligence**: Comprehensive threat categorization and source tracking
- **Interactive Dashboard**: Modern, responsive UI with real-time charts and metrics
- **System Configuration**: Adjustable detection settings and model performance monitoring
- **Clean Interface**: Minimalist design focused on functionality

## Quick Start

### Prerequisites

- Python 3.8+
- Streamlit

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd nid-project
```

2. Install dependencies:
```bash
pip install streamlit pandas numpy joblib plotly
```

3. Run the application:
```bash
streamlit run simple_nid.py
```

4. Open your browser to `http://localhost:8501`

## Usage

1. **Start Monitoring**: Click "Start Monitoring" in the sidebar to begin real-time analysis
2. **View Dashboard**: Monitor network traffic, protocols, and connection statistics
3. **Analyze Threats**: Switch to the Threats tab to view threat intelligence and analytics
4. **Configure Settings**: Access system configuration and model performance metrics

## Project Structure

```
NID Project/
├── simple_nid.py          # Main Streamlit application
├── README.md              # This file
├── LICENSE                # MIT License
└── requirements.txt       # Python dependencies
```

## Technology Stack

- **Frontend**: Streamlit
- **Data Processing**: Pandas, NumPy
- **Visualization**: Plotly
- **Model Persistence**: Joblib

## Deployment

### Streamlit Cloud

1. Push your code to GitHub
2. Connect your GitHub repository to [Streamlit Cloud](https://share.streamlit.io/)
3. Deploy with the following settings:
   - **Main file path**: `simple_nid.py`
   - **Python version**: 3.8+

### Local Deployment

```bash
streamlit run simple_nid.py --server.port 8501
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository.

---

**Network Intrusion Detector** - Advanced Network Security Monitoring & Threat Analysis
