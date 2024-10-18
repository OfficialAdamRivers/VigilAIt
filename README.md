# VigilAIt

VigilAIt is a security tool that provides threat detection, event logging, and playbook execution for network security.

## Features
- User authentication with Flask
- Real-time packet sniffing and analysis
- Machine learning model for threat detection
- Integration with VirusTotal for malware analysis

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/OfficialAdamRivers/VigilAIt.git
   cd VigilAIt
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Create the necessary configuration files:
   - Edit `config/config.yaml` to include your configurations.
   - Create `config/api_keys.json` with your API keys.

4. Run the application:
   ```bash
   python vigilait/main.py
   ```

## Usage
Access the web interface at `http://localhost:5000`.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
