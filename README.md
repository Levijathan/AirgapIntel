# AirgapIntel

## Description

**AirgapIntel** is a Python script designed to download Open Source Intelligence (OSINT) feeds from various sources for offline use
especially in air-gapped environments. It automates the process of fetching and organizing threat intelligence feeds from sources
like CIRCL, Malware Bazaar, Threatfox, URLhaus, Botvrij, and other generic directory listings and direct download URLs as listed
on the [MISP Feed List](https://www.misp-project.org/feeds/).

This script is ideal for users who need to import MISP-compatible OSINT feeds into air-gapped or offline systems,
where direct internet access for feed synchronization is restricted.

<img width="718" alt="AirgapIntel" src="https://github.com/user-attachments/assets/6d8e7254-1ffc-4d7c-83a6-f18781e8a7c3" />

## Key Features

  * **Offline Intel Feed Preparation:** Downloads and structures OSINT feeds for seamless import into air-gapped environments.
  * **Multi-Source Support:**  Fetches feeds from a variety of reputable OSINT providers, including:
      * CIRCL (Computer Incident Response Center Luxembourg)
      * Malware Bazaar (abuse.ch)
      * Threatfox (abuse.ch)
      * URLhaus (abuse.ch)
      * Botvrij.eu
      * TweetFeed (via raw GitHub content)
      * All feeds from misp-project.org/feeds/
  * **Date-Based Filtering:** Downloads feed files for a specified number of past days (configurable), allowing you to manage the freshness and volume of downloaded data.
  * **Feed Categorization:** Organizes downloaded feeds into categories (e.g., CIRCL Feeds, Malware Bazaar Feeds) for better management.
  * **Error Logging:**  Logs any errors encountered during the download process to a CSV log file for easy troubleshooting.
  * **Windows-Compatible Filenames:** Sanitizes filenames to ensure compatibility with Windows file systems.
  * **Simple Operation:** Easy-to-use command-line interface.

## Prerequisites

  * **Python 3.6 or higher:**  Make sure you have Python 3 installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

  * **Python Libraries:** Install the required Python libraries using pip:

    ```bash
    pip install requests beautifulsoup4
    ```

## Installation

1.  **Download the Script:** Download the `airgapintel.py` (or `airgap_intel.py`, depending on which filename you chose) script from this GitHub repository.
2.  **Place the Script:**  Save the script to a directory on your system where you want to store the downloaded feeds.

## Usage

1.  **Open a Terminal or Command Prompt:** Navigate to the directory where you saved `airgapintel.py` (or `airgap_intel.py`).

2.  **Run the Script:** Execute the script using Python:

    ```bash
    python airgapintel.py  # Or python airgap_intel.py, if you used that filename
    ```

3.  **Follow Prompts:**

      * The script will prompt you to enter the number of days back you want to download feeds for (default is 7 days). You can press Enter to use the default, or type in a number and press Enter.
      * Press Enter again when prompted to begin the download process.

4.  **Output:**

      * The script will display informative messages about the feed categories being processed and the feeds being downloaded.
      * Downloaded feeds will be saved in a directory named `AirgapIntel_Feeds` created in the same directory where you run the script. Feeds are further organized into subdirectories based on their category and name.
      * A log file named `misp_feed_download_log.csv` will also be created in the `AirgapIntel_Feeds` directory, logging the date, time, run duration, and any errors encountered.

5.  **Air-Gap System Import:** After the script completes, you can transfer the `AirgapIntel_Feeds` directory to your air-gapped system.

## Disclaimer and License

**Disclaimer:**

This script is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the script or the use or other dealings in the script. Use this script at your own risk. Always ensure compliance with the terms of service and usage policies of the feed sources you are downloading from.

**License:**

This project is licensed under the **GPLv3 License** - visit [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Author

James Levija

## Contributing

Contributions to improve the script are welcome\! Please feel free to fork the repository, make your changes, and submit a pull request.

## Follow-on Script

Follow-on script to import the feeds into MariaDB on MISP can be found here: [AirgapSync](https://github.com/Levijathan/AirgapSync)
