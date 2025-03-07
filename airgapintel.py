"""
Airgap Intel

Description:
    This Python script downloads Open Source Intelligence (OSINT) feeds from various
    sources for offline use, particularly in air-gapped MISP (Malware Information
    Sharing Platform) environments. It supports downloading feeds from CIRCL,
    Malware Bazaar, Threatfox, URLhaus, Botvrij, and other generic directory
    listings and direct download URLs listed on the MISP Feed List.

Features:
    - Downloads and organizes MISP OSINT feeds for offline/air-gapped use.
    - Supports multiple feed types and date-based filtering.
    - Includes feed-level progress bars and error logging. (Progress bars removed in this version)
    - Sanitizes filenames for Windows compatibility.

Author: James Levija

License:
    GPLv3 (GNU General Public License v3.0): https://www.gnu.org/licenses/gpl-3.0.en.html
    (For full license text, see the link above or the LICENSE file in the repository)

Disclaimer:
    This script is provided "as is", without warranty of any kind, express or implied,
    including but not limited to the warranties of merchantability,
    fitness for a particular purpose and noninfringement. In no event shall the
    authors or copyright holders be liable for any claim, damages or other
    liability, whether in an action of contract, tort or otherwise, arising from,
    out of or in connection with the script or the use or other dealings in the script.
    Use this script at your own risk. Always ensure compliance with the terms of service
    and usage policies of the feed sources you are downloading from.

Purpose:
    This script is intended for educational and informational purposes.
    Use it responsibly and ethically for cybersecurity and threat intelligence research.

Please ensure you have reviewed and understood the license and disclaimer before using this script.
"""

import os
import requests
import datetime
import csv
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import re  # Import the regular expression module

# Configuration
BASE_URL = "https://www.misp-project.org/feeds/"
OUTPUT_DIR = "AirgapIntel_Feeds"
LOG_FILE = os.path.join(OUTPUT_DIR, "misp_feed_download_log.csv")
DAYS_BACK_DEFAULT = 7  # Default days back to retrieve files

successful_feed_count = 0  # Initialize a global counter for successful feeds

def ascii_art():
    """Prints ASCII art for MISP Airgap Feeds."""
    print(r"""
 _______ _________ _______  _______  _______  _______   _________ _       _________ _______  _       
(  ___  )\__   __/(  ____ )(  ____ \(  ___  )(  ____ )  \__   __/( (    /|\__   __/(  ____ \( \      
| (   ) |   ) (   | (    )|| (    \/| (   ) || (    )|     ) (   |  \  ( |   ) (   | (    \/| (      
| (___) |   | |   | (____)|| |      | (___) || (____)|     | |   |   \ | |   | |   | (__    | |      
|  ___  |   | |   |     __)| | ____ |  ___  ||  _____)     | |   | (\ \) |   | |   |  __)   | |      
| (   ) |   | |   | (\ (   | | \_  )| (   ) || (           | |   | | \   |   | |   | (      | |      
| )   ( |___) (___| ) \ \__| (___) || )   ( || )        ___) (___| )  \  |   | |   | (____/\| (____/\
|/     \|\_______/|/   \__/(_______)|/     \||/         \_______/|/    )_)   )_(   (_______/(_______/
                                                                                                     
    """)

def download_feed_file(feed_url, output_folder, feed_name):
    """Downloads a feed file and saves it to the specified folder (general direct download)."""
    HEADERS_DIRECT_DOWNLOAD = {  # Define headers for direct downloads
        "User-Agent": "Mozilla/5.0 (compatible; MISPFeedDownloader/1.0)"
    }
    try:
        response = requests.get(feed_url, headers=HEADERS_DIRECT_DOWNLOAD, timeout=60)  # Increased timeout to 60 seconds
        response.raise_for_status()

        filename = os.path.basename(urlparse(feed_url).path)
        output_path = os.path.join(output_folder, filename)

        with open(output_path, "wb") as f:
            f.write(response.content)

        return True, None
    except requests.exceptions.RequestException as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def is_directory_listing_url(url):
    """Heuristic to determine if a URL is likely a directory listing."""
    parsed_url = urlparse(url)
    return parsed_url.path.endswith('/') or not parsed_url.path

def fetch_directory_page_content(url, headers, timeout):
    """Fetches content of a directory listing page."""
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR - fetch_directory_page_content] Failed to fetch directory listing page: {url}: {e}")
        return None

def download_individual_file(url, directory, filename, session):
    """Downloads a single file (used for directory listings).""" # Description updated - progress bar removed
    local_filename = os.path.join(directory, filename)
    try:
        with session.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            block_size = 1024  # 1 Kibibyte
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(block_size):
                    f.write(chunk)
            return True, None
    except requests.RequestException as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def is_circl_feed_url(url):
    """Checks if a URL is a CIRCL feed URL based on the base URL."""
    circl_base_url_pattern = "/doc/misp/feed-osint"
    return circl_base_url_pattern in urlparse(url).path

def download_circl_feed(directory_url, output_folder, feed_name, log_data, days_back=DAYS_BACK_DEFAULT): # Use DAYS_BACK_DEFAULT
    """Downloads CIRCL feed files from a directory listing with date-based filtering."""
    try:
        html_content = fetch_circl_page_content(directory_url)
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch CIRCL feed page")
            return False

        date_list = get_circl_date_list(days_back)
        file_links = parse_circl_files(html_content, directory_url, date_list)
        if not file_links:
            print(f"[INFO - download_circl_feed] No CIRCL files found for the past {days_back} days for {feed_name} at {directory_url}")
            return True

        for file_info in file_links:
            success, error = download_feed_file(file_info['url'], output_folder, file_info['filename'])
            if not success:
                log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing CIRCL feed: {e}")
        return False

def fetch_circl_page_content(url):
    """Fetches the HTML content of the CIRCL feed page."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR - fetch_circl_page_content] Failed to fetch CIRCL page: {url}: {e}")
        return None

def get_circl_date_list(days_back):
    """Generates a list of dates to check for CIRCL files."""
    today = datetime.datetime.now()
    date_list = [(today - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days_back)]
    return date_list

def parse_circl_files(html_content, base_url, date_list):
    """Parses HTML content to extract CIRCL file links based on date."""
    soup = BeautifulSoup(html_content, "html.parser")
    files = []

    for row in soup.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

        link_tag = cols[1].find("a")
        if link_tag and link_tag.get('href'):
            file_url = urljoin(base_url, link_tag.get('href'))
            filename = os.path.basename(urlparse(file_url).path)
            last_modified = cols[2].get_text(strip=True)

            if any(last_modified.startswith(date) for date in date_list):
                files.append({'url': file_url, 'filename': filename})

    return files

def is_malwarebazaar_feed_url(url):
    """Checks if a URL is a Malware Bazaar feed URL based on the base URL."""
    malwarebazaar_base_url_pattern = "/downloads/misp/"
    return malwarebazaar_base_url_pattern in urlparse(url).path

def download_malwarebazaar_feed(directory_url, output_folder, feed_name, log_data, days_back=DAYS_BACK_DEFAULT): # Use DAYS_BACK_DEFAULT
    """Downloads Malware Bazaar feed files for the past days_back days."""
    try:
        html_content = fetch_malwarebazaar_page_content(directory_url)
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch Malware Bazaar feed page")
            return False

        date_list = get_malwarebazaar_date_list(days_back)
        file_links = parse_malwarebazaar_files(html_content, directory_url, date_list)
        if not file_links:
            print(f"[INFO - download_malwarebazaar_feed] No Malware Bazaar files found for the past {days_back} days for {feed_name} at {directory_url}")
            return True

        for file_info in file_links:
            success, error = download_feed_file(file_info['url'], output_folder, file_info['filename'])
            if not success:
                log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing Malware Bazaar feed: {e}")
        return False

def fetch_malwarebazaar_page_content(url):
    """Fetches the HTML content of the Malware Bazaar feed page."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR - fetch_malwarebazaar_page_content] Failed to fetch Malware Bazaar page: {url}: {e}")
        return None

def get_malwarebazaar_date_list(days_back):
    """Generates a list of dates to check for Malware Bazaar files (reusing CIRCL's date list logic)."""
    return get_circl_date_list(days_back)

def parse_malwarebazaar_files(html_content, base_url, date_list):
    """Parses HTML content to extract Malware Bazaar file links based on date."""
    soup = BeautifulSoup(html_content, "html.parser")
    files = []

    for row in soup.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

        link_tag = cols[1].find("a")
        if link_tag and link_tag.get('href'):
            file_url = urljoin(base_url, link_tag.get('href'))
            filename = os.path.basename(urlparse(file_url).path)
            last_modified = cols[2].get_text(strip=True)

            if any(last_modified.startswith(date) for date in date_list):
                files.append({'url': file_url, 'filename': filename})

    return files

def is_threatfox_feed_url(url):
    """Checks if a URL is a Threatfox feed URL based on the base URL."""
    threatfox_base_url_pattern = "/downloads/misp/"
    return threatfox_base_url_pattern in urlparse(url).path

def download_threatfox_feed(directory_url, output_folder, feed_name, log_data, days_back=DAYS_BACK_DEFAULT): # Use DAYS_BACK_DEFAULT
    """Downloads Threatfox feed files for the past days_back days."""
    try:
        html_content = fetch_threatfox_page_content(directory_url)
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch Threatfox feed page")
            return False

        date_list = get_threatfox_date_list(days_back)
        file_links = parse_threatfox_files(html_content, directory_url, date_list)
        if not file_links:
            print(f"[INFO - download_threatfox_feed] No Threatfox files found for the past {days_back} days for {feed_name} at {directory_url}")
            return True

        for file_info in file_links:
            success, error = download_feed_file(file_info['url'], output_folder, file_info['filename'])
            if not success:
                log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing Threatfox feed: {e}")
        return False

def fetch_threatfox_page_content(url):
    """Fetches the HTML content of the Threatfox feed page."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR - fetch_threatfox_page_content] Failed to fetch Threatfox page: {url}: {e}")
        return None

def get_threatfox_date_list(days_back):
    """Generates a list of dates to check for Threatfox files (reusing existing date list logic)."""
    return get_circl_date_list(days_back)

def parse_threatfox_files(html_content, base_url, date_list):
    """Parses HTML content to extract Threatfox file links based on date."""
    soup = BeautifulSoup(html_content, "html.parser")
    files = []

    for row in soup.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

        link_tag = cols[1].find("a")
        if link_tag and link_tag.get('href'):
            file_url = urljoin(base_url, link_tag.get('href'))
            filename = os.path.basename(urlparse(file_url).path)
            last_modified = cols[2].get_text(strip=True)

            if any(last_modified.startswith(date) for date in date_list):
                files.append({'url': file_url, 'filename': filename})

    return files

def is_urlhaus_feed_url(url):
    """Checks if a URL is a URLhaus feed URL based on the base URL."""
    urlhaus_base_url_pattern = "/downloads/misp/"
    return urlhaus_base_url_pattern in urlparse(url).path

def download_urlhaus_feed(directory_url, output_folder, feed_name, log_data, days_back=DAYS_BACK_DEFAULT): # Use DAYS_BACK_DEFAULT
    """Downloads URLhaus feed files for the past days_back days."""
    HEADERS_URLHAUS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        html_content = fetch_urlhaus_page_content(directory_url, HEADERS_URLHAUS)
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch URLhaus feed page")
            return False

        date_list = get_urlhaus_date_list(days_back)
        file_links = parse_urlhaus_files(html_content, directory_url, date_list)
        if not file_links:
            print(f"[INFO - download_urlhaus_feed] No URLhaus files found for the past {days_back} days for {feed_name} at {directory_url}")
            return True

        for file_info in file_links:
            success, error = download_feed_file(file_info['url'], output_folder, file_info['filename'])
            if not success:
                log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing URLhaus feed: {e}")
        return False

def fetch_urlhaus_page_content(url, headers):
    """Fetches the HTML content of the URLhaus feed page, including User-Agent header."""
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR - fetch_urlhaus_feed] Failed to fetch URLhaus page: {url}: {e}")
        return None

def get_urlhaus_date_list(days_back):
    """Generates date list for URLhaus (reusing existing date list logic)."""
    return get_circl_date_list(days_back)

def parse_urlhaus_files(html_content, base_url, date_list):
    """Parses HTML content to extract URLhaus file links based on date."""
    soup = BeautifulSoup(html_content, "html.parser")
    files = []

    for row in soup.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

        link_tag = cols[1].find("a")
        if link_tag and link_tag.get('href'):
            file_url = urljoin(base_url, link_tag.get('href'))
            filename = os.path.basename(urlparse(file_url).path)
            last_modified = cols[2].get_text(strip=True)

            if any(last_modified.startswith(date) for date in date_list):
                files.append({'url': file_url, 'filename': filename})

    return files

def is_tweetfeed_url(url):
    """Checks if a URL is a TweetFeed URL based on the base URL."""
    tweetfeed_base_url_pattern = "raw.githubusercontent.com/0xDanielLopez/TweetFeed"
    return tweetfeed_base_url_pattern in urlparse(url).netloc + urlparse(url).path

def sanitize_filename(filename):
    """Sanitizes a filename or directory name to be Windows-compatible."""
    # Replace invalid characters with underscores
    sanitized_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading and trailing spaces and dots
    sanitized_name = sanitized_name.strip(' .')
    # Limit filename length (Windows MAX_PATH is 260, keep some buffer)
    sanitized_name = sanitized_name[:240]
    return sanitized_name

def parse_botvrij_listing_content(html_content, base_url):
    """Parses HTML content specifically for Botvrij to extract JSON file links."""
    soup = BeautifulSoup(html_content, 'html.parser')
    file_links = []
    pre_tag = soup.find('pre')
    if not pre_tag:
        print("[ERROR - parse_botvrij_listing_content] <pre> tag not found in Botvrij directory listing HTML.")
        return file_links

    for a_tag in pre_tag.find_all('a'):
        href = a_tag.get('href', '')
        if href.endswith('.json'):  # <--- Specific to Botvrij: Only get JSON files
            file_url = urljoin(base_url, href)
            filename = href # Use href directly as filename for Botvrij as per provided script
            file_links.append({
                "filename": filename,
                "url": file_url
            })

    return file_links

def download_botvrij_feed(directory_url, output_folder, feed_name, log_data):
    """Downloads Botvrij feed files, specifically JSON files from directory listing."""
    HEADERS_BOTVRIJ = {
        "User-Agent": "Mozilla/5.0 (compatible; IntelScraperBot/1.0)" # Using User-Agent from provided Botvrij script
    }
    TIMEOUT_BOTVRIJ = 30

    try:
        # Ensure directory_url ends with '/' for correct urljoin behavior
        if not directory_url.endswith('/'):
            directory_url += '/'

        html_content = fetch_directory_page_content(directory_url, HEADERS_BOTVRIJ, TIMEOUT_BOTVRIJ) # Reusing fetch_directory_page_content
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch Botvrij directory listing page")
            return False

        file_links = parse_botvrij_listing_content(html_content, directory_url) # Using dedicated parser for Botvrij
        if not file_links:
            print(f"[WARNING - download_botvrij_feed] No JSON files found in Botvrij directory listing for {feed_name} at {directory_url}")
            return True

        with requests.Session() as session:
            session.headers.update(HEADERS_BOTVRIJ) # Use Botvrij specific headers
            for file_info in file_links:
                success, error = download_individual_file(file_info['url'], output_folder, file_info['filename'], session) # Reusing download_individual_file
                if not success:
                    log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing Botvrij feed: {e}")
        return False

def download_directory_listing_feed(directory_url, output_folder, feed_name, log_data):
    """Downloads all files from a generic directory listing page."""
    HEADERS_DIRECTORY_LISTING = {  # Define headers for generic directory listing
        "User-Agent": "Mozilla/5.0 (compatible; GenericDirectoryDownloader/1.0)"
    }
    TIMEOUT_DIRECTORY_LISTING = 30

    try:
        # Ensure directory_url ends with '/' for correct urljoin behavior
        if not directory_url.endswith('/'):
            directory_url += '/'

        html_content = fetch_directory_page_content(directory_url, HEADERS_DIRECTORY_LISTING, TIMEOUT_DIRECTORY_LISTING) # Reusing fetch_directory_page_content
        if not html_content:
            log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Failed to fetch directory listing page")
            return False

        file_links = parse_directory_listing_content(html_content, directory_url) # Using generic parser
        if not file_links:
            print(f"[WARNING - download_directory_listing_feed] No files found in directory listing for {feed_name} at {directory_url}")
            return True # Not an error, just no files found

        with requests.Session() as session:
            session.headers.update(HEADERS_DIRECTORY_LISTING) # Use generic headers
            for file_info in file_links:
                success, error = download_individual_file(file_info['url'], output_folder, file_info['filename'], session) # Reusing download_individual_file with progress
                if not success:
                    log_data["error_feeds"].append(f"{feed_name} - File {file_info['filename']} ({file_info['url']}): {error}")
        return True

    except Exception as e:
        log_data["error_feeds"].append(f"{feed_name} ({directory_url}): Error processing directory listing feed: {e}")
        return False

def parse_directory_listing_content(html_content, base_url):
    """Parses HTML content from a directory listing to extract file links (generic)."""
    soup = BeautifulSoup(html_content, 'html.parser')
    file_links = []
    # Look for links in <pre> tags (common in simple directory listings)
    pre_tag = soup.find('pre')
    if pre_tag:
        for a_tag in pre_tag.find_all('a'):
            href = a_tag.get('href')
            if href and not href.startswith('?') and not href.startswith('..'): # Exclude CGI params and parent dir links
                file_url = urljoin(base_url, href)
                filename = os.path.basename(urlparse(file_url).path)
                file_links.append({
                    "filename": filename,
                    "url": file_url
                })
        if file_links:
            return file_links

    # If not in <pre>, try parsing <a> tags more broadly (for more complex listings)
    for a_tag in soup.find_all('a'):
        href = a_tag.get('href')
        if href and not href.startswith('?') and not href.startswith('..'):
            file_url = urljoin(base_url, href)
            filename = os.path.basename(urlparse(file_url).path)
            file_links.append({
                "filename": filename,
                "url": file_url
            })
    return file_links


def process_single_feed(url, name, output_dir, log_data, days_back=DAYS_BACK_DEFAULT): # Accept days_back as argument
    """Processes a single feed and downloads it. Handles different feed types."""
    global successful_feed_count  # Use the global counter

    try:
        # Sanitize the feed name for directory creation
        sanitized_feed_name = sanitize_filename(name)
        feed_folder = os.path.join(output_dir, sanitized_feed_name)
        os.makedirs(feed_folder, exist_ok=True)

        if "botvrij" in name.lower(): # Check for Botvrij FIRST -  important to use dedicated function
            print(f"[INFO] Processing Botvrij feed: {name} from {url}")
            success = download_botvrij_feed(url, feed_folder, name, log_data) # Use dedicated Botvrij function
        elif is_tweetfeed_url(url):  # Check for TweetFeed URLs
            print(f"[INFO] Processing TweetFeed: {name} from {url} (direct download)")
            success, error = download_feed_file(url, feed_folder, name)  # Treat as direct download - reuse download_feed_file
            if not success:
                log_data["error_feeds"].append(f"{name} ({url}): {error}")
                return
        elif is_urlhaus_feed_url(url):  # Then check for URLhaus URLs
            print(f"[INFO] Processing URLhaus feed: {name} from {url}")
            success = download_urlhaus_feed(url, feed_folder, name, log_data, days_back=days_back) # Pass days_back
        elif is_threatfox_feed_url(url):  # Then check for Threatfox URLs
            print(f"[INFO] Processing Threatfox feed: {name} from {url}")
            success = download_threatfox_feed(url, feed_folder, name, log_data, days_back=days_back) # Pass days_back
        elif is_malwarebazaar_feed_url(url):  # Then check for Malware Bazaar URLs
            print(f"[INFO] Processing Malware Bazaar feed: {name} from {url}")
            success = download_malwarebazaar_feed(url, feed_folder, name, log_data, days_back=days_back) # Pass days_back
        elif is_circl_feed_url(url):  # Then check for CIRCL URLs
            print(f"[INFO] Processing CIRCL feed: {name} from {url}")
            success = download_circl_feed(url, feed_folder, name, log_data, days_back=days_back) # Pass days_back
        elif is_directory_listing_url(url):  # Then check for generic directory listings (AFTER Botvrij)
            print(f"[INFO] Processing directory listing feed: {name} from {url}")
            success = download_directory_listing_feed(url, feed_folder, name, log_data) # Use generic directory listing for others, EXCEPT Botvrij
        else:  # Otherwise, assume it's a direct download (for other types)
            print(f"[INFO] Processing direct download feed: {name} from {url}")
            success, error = download_feed_file(url, feed_folder, name)  # Use general download function
            if not success:
                log_data["error_feeds"].append(f"{name} ({url}): {error}")
                return

        if success:
            global successful_feed_count  # Access the global counter
            successful_feed_count += 1  # Increment successful download count
        # else: # No need for else here, errors are handled in download_*_feed functions

    except Exception as e:
        log_data["error_feeds"].append(f"{name}: {e}")

def fetch_feed_list():
    """Fetches the list of feeds from the MISP website (using provided HTML) and includes TweetFeed URLs."""
    # --- Using provided HTML content directly WITH TWEETFEED URLs ---
    html_content = """
    <ul><li><a href="https://sslbl.abuse.ch/blacklist/sslblacklist.csv">abuse.ch SSL IPBL</a> - abuse.ch - feed format: csv</li><li><a href="https://reputation.alienvault.com/reputation.generic">alienvault reputation generic</a> - .alienvault.com - feed format: csv</li><li><a href="https://osint.bambenekconsulting.com/feeds/dga-feed-high.csv">All current domains belonging to known malicious DGAs</a> - osint.bambenekconsulting.com - feed format: csv</li><li><a href="https://lists.blocklist.de/lists/all.txt">blocklist.de/lists/all.txt</a> - blocklist.de - feed format: freetext</li><li><a href="https://blocklist.greensnow.co/greensnow.txt">blocklist.greensnow.co</a> - greensnow.co - feed format: csv</li><li><a href="https://rules.emergingthreats.net/blockrules/compromised-ips.txt">blockrules of rules.emergingthreats.net</a> - rules.emergingthreats.net - feed format: csv</li><li><a href="https://cinsscore.com/list/ci-badguys.txt">ci-badguys.txt</a> - cinsscore.com - feed format: freetext</li><li><a href="https://www.circl.lu/doc/misp/feed-osint/">CIRCL OSINT Feed</a> - CIRCL - feed format: misp</li><li><a href="https://cybercrime-tracker.net/all.php">cybercrime-tracker.net - all</a> - cybercrime-tracker.net - feed format: freetext</li><li><a href="https://api.cybercure.ai/feed/get_url?type=csv">CyberCure - Blocked URL Feed</a> - <a href="https://www.cybercure.ai">www.cybercure.ai</a> - feed format: csv</li><li><a href="https://api.cybercure.ai/feed/get_hash?type=csv">CyberCure - Hash Feed</a> - <a href="https://www.cybercure.ai">www.cybercure.ai</a> - feed format: csv</li><li><a href="https://api.cybercure.ai/feed/get_ips?type=csv">CyberCure - IP Feed</a> - <a href="https://www.cybercure.ai">www.cybercure.ai</a> - feed format: csv</li><li><a href="https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt">diamondfox_panels</a> - pan-unit42 - feed format: freetext</li><li><a href="https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/">DigitalSide Threat-Intel OSINT Feed</a> - osint.digitalside.it - feed format: directory listing</li><li><a href="https://dataplane.org/dnsversion.txt">DNS CH TXT version.bind</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/dnsrdany.txt">DNS recursion desired IN ANY</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/dnsrd.txt">DNS recursion desired</a> - dataplane.org - feed format: csv</li><li><a href="https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt">Domains from High-Confidence DGA-based C&amp;C Domains Actively Resolving</a> - osint.bambenekconsulting.com - feed format: csv</li><li><a href="https://cdn.ellio.tech/community-feed">ELLIO: IP Feed (Community version)</a> - ellio.tech - feed format: freetext</li><li><a href="https://feodotracker.abuse.ch/downloads/ipblocklist.csv">Feodo IP Blocklist</a> - abuse.ch - feed format: csv</li><li><a href="https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset">firehol_level1</a> - iplists.firehol.org - feed format: freetext</li><li><a href="https://cybercrime-tracker.net/ccamgate.php">http://cybercrime-tracker.net gatelist</a> - <a href="http://cybercrime-tracker.net">http://cybercrime-tracker.net</a> gatelist - feed format: freetext</li><li><a href="https://cybercrime-tracker.net/ccamlist.php">http://cybercrime-tracker.net hashlist</a> - <a href="http://cybercrime-tracker.net">http://cybercrime-tracker.net</a> hashlist - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/misp/infoblox-threat-intelligence.json">Infobox-Threat-Intelligence</a> - infobox.com - feed format: misp</li><li><a href="https://dataplane.org/proto41.txt">IP protocol 41</a> - dataplane.org - feed format: csv</li><li><a href="https://snort.org/downloads/ip-block-list">ip-block-list - snort.org</a> - <a href="https://snort.org">https://snort.org</a> - feed format: freetext</li><li><a href="https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt">IPs from High-Confidence DGA-Based C&amp;Cs Actively Resolving - requires a valid license</a> - osint.bambenekconsulting.com - feed format: csv</li><li><a href="http://www.ipspamlist.com/public_feeds.csv">ipspamlist</a> - ipspamlist - feed format: csv</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt">IPsum (aggregation of all feeds) - level 1 - lot of false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt">IPsum (aggregation of all feeds) - level 2 - medium false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt">IPsum (aggregation of all feeds) - level 3 - low false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt">IPsum (aggregation of all feeds) - level 4 - very low false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt">IPsum (aggregation of all feeds) - level 5 - ultra false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt">IPsum (aggregation of all feeds) - level 6 - no false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt">IPsum (aggregation of all feeds) - level 7 - no false positives</a> - IPsum - feed format: freetext</li><li><a href="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt">IPsum (aggregation of all feeds) - level 8 - no false positives</a> - IPsum - feed format: freetext</li><li><a href="https://jamesbrine.com.au/csv">James Brine Bruteforce IPs</a> - jamesbrine.com.au - feed format: csv</li><li><a href="https://hole.cert.pl/domains/domains.txt">List of malicious domains in Poland</a> - CERT-PL - feed format: freetext</li><li><a href="https://cti.bb.com.br:8443/hash-list.csv">List of malicious hashes</a> - Banco do Brasil S.A - feed format: csv</li><li><a href="https://malshare.com/daily/malshare.current.all.txt">malshare.com - current all</a> - malshare.com - feed format: freetext</li><li><a href="https://malsilo.gitlab.io/feeds/dumps/domain_list.txt">malsilo.domain</a> - MalSilo - feed format: csv</li><li><a href="https://malsilo.gitlab.io/feeds/dumps/ip_list.txt">malsilo.ipv4</a> - MalSilo - feed format: csv</li><li><a href="https://malsilo.gitlab.io/feeds/dumps/url_list.txt">malsilo.url</a> - MalSilo - feed format: csv</li><li><a href="https://bazaar.abuse.ch/export/txt/md5/recent/">Malware Bazaar</a> - abuse.ch - feed format: csv</li><li><a href="https://bazaar.abuse.ch/downloads/misp/">MalwareBazaar</a> - abuse.ch - feed format: misp</li><li><a href="https://feeds.ecrimelabs.net/data/metasploit-cve">Metasploit exploits with CVE assigned</a> - eCrimeLabs - feed format: csv</li><li><a href="https://mirai.security.gives/data/ip_list.txt">mirai.security.gives</a> - security.gives - feed format: freetext</li><li><a href="https://openphish.com/feed.txt">OpenPhish url list</a> - openphish.com - feed format: freetext</li><li><a href="https://phishstats.info/phish_score.csv">PhishScore</a> - PhishStats - feed format: csv</li><li><a href="https://data.phishtank.com/data/online-valid.csv">Phishtank online valid phishing</a> - Phishtank - feed format: csv</li><li><a href="https://home.nuug.no/~peter/pop3gropers.txt">pop3gropers</a> - home.nuug.no - feed format: csv</li><li><a href="https://shreshtait.com/newly-registered-domains/nrd-1m">Shreshta: Newly Registered domain names (NRD) - 1 month (Community policy feed)</a> - shreshtait.com - feed format: freetext</li><li><a href="https://shreshtait.com/newly-registered-domains/nrd-1w">Shreshta: Newly Registered domain names(NRD) - 1 week (Community policy feed)</a> - shreshtait.com - feed format: freetext</li><li><a href="https://dataplane.org/sipinvitation.txt">sipinvitation</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/sipquery.txt">sipquery</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/sipregistration.txt">sipregistration</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/smtpdata.txt">SMTP data</a> - dataplane.org - feed format: csv</li><li><a href="https://dataplane.org/smtpgreet.txt">SMTP greet</a> - dataplane.org - feed format: csv</li><li><a href="https://feeds.honeynet.asia/bruteforce/latest-sshbruteforce-unique.csv">SSH Bruteforce IPs</a> - APNIC Community Honeynet Project - feed format: csv</li><li><a href="https://dataplane.org/sshpwauth.txt">sshpwauth.txt</a> - dataplane.org - feed format: csv</li><li><a href="https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv">Telnet Bruteforce IPs</a> - APNIC Community Honeynet Project - feed format: csv</li><li><a href="https://dataplane.org/telnetlogin.txt">TELNET login</a> - dataplane.org - feed format: csv</li><li><a href="https://www.botvrij.eu/data/feed-osint">The Botvrij.eu Data</a> - Botvrij.eu - feed format: misp</li>
<li><a href="https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_browser.txt?inline=false">This list contains all browser mining domains - A list to prevent browser mining only</a> - ZeroDot1 - CoinBlockerLists - feed format: freetext</li><li><a href="https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt?inline=false">This list contains all domains - A list for administrators to prevent mining in networks</a> - ZeroDot1 - CoinBlockerLists - feed format: freetext</li><li><a href="https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt?inline=false">This list contains all optional domains - An additional list for administrators</a> - ZeroDot1 - CoinBlockerLists - feed format: freetext</li><li><a href="https://threatfox.abuse.ch/export/csv/recent/">threatfox indicators of compromise</a> - abuse.ch - feed format: csv</li><li><a href="https://threatfox.abuse.ch/downloads/misp/">Threatfox</a> - abuse.ch - feed format: misp</li><li><a href="https://threatview.io/Downloads/MALICIOUS-BITCOIN_FEED.txt">Threatview.io - Bitcoin Address Intel</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt">Threatview.io - C2 Hunt Feed</a> - threatview.io - feed format: csv</li><li><a href="https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt">Threatview.io - Domain Blocklist</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/IP-High-Confidence-Feed.txt">Threatview.io - IP Blocklist</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/MD5-HASH-ALL.txt">Threatview.io - MD5 Hash Blocklist</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/Experimental-IOC-Tweets.txt">Threatview.io - OSINT Threat Feed</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/SHA-HASH-FEED.txt">Threatview.io - SHA File Hash Blocklist</a> - threatview.io - feed format: freetext</li><li><a href="https://threatview.io/Downloads/URL-High-Confidence-Feed.txt">Threatview.io - URL Blocklist</a> - threatview.io - feed format: freetext</li><li><a href="https://www.dan.me.uk/torlist/">Tor ALL nodes</a> - TOR Node List from dan.me.uk - careful, this feed applies a lock-out after each pull. This is shared with the &ldquo;Tor exit nodes&rdquo; feed. - feed format: csv</li><li><a href="https://www.dan.me.uk/torlist/?exit">Tor exit nodes</a> - TOR Node List from dan.me.uk - careful, this feed applies a lock-out after each pull. This is shared with the &ldquo;Tor ALL nodes&rdquo; feed. - feed format: csv</li><li><a href="https://feeds.honeynet.asia/url/latest-url-unique.csv">URL Seen in honeypots</a> - APNIC Community Honeynet Project - feed format: freetext</li><li><a href="https://urlhaus.abuse.ch/downloads/csv_recent/">URLHaus Malware URLs</a> - abuse.ch - feed format: csv</li><li><a href="https://urlhaus.abuse.ch/downloads/misp/">URLhaus</a> - abuse.ch - feed format: misp</li><li><a href="https://dataplane.org/vncrfb.txt">VNC RFB</a> - dataplane.org - feed format: csv</li><li><a href="http://vxvault.net/URL_List.php">VXvault - URL List</a> - VXvault - feed format: freetext</li>
        <li><a href="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv">TweetFeed Week URL</a> - TweetFeed - feed format: csv (URL)</li>
        <li><a href="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv">TweetFeed Week DNS</a> - TweetFeed - feed format: csv (DNS)</li>
        <li><a href="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv">TweetFeed Week IP</a> - TweetFeed - feed format: csv (IP)</li>
        <li><a href="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv">TweetFeed Week SHA256</a> - TweetFeed - feed format: csv (SHA256)</li>
        <li><a href="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv">TweetFeed Week MD5</a> - TweetFeed - feed format: csv (MD5)</li>
    </ul>
    """
    soup = BeautifulSoup(html_content, "html.parser")

    feed_data = []

    for li in soup.find_all("li"):
        link = li.find("a")
        if link and "href" in link.attrs:
            url = link["href"].strip()
            if not url.startswith("http"):
                url = urljoin(BASE_URL, url)  # This line might be unnecessary now for test HTML
            name = link.text.strip()
            feed_data.append((url, name.replace("/", "-")))

    if not feed_data:
        print("Warning: No feeds found in the provided HTML.")
                
        # --- ADD ADDITIONAL FEEDS HERE ---
        # If downloading from GitHub, make sure you use the raw user content link, otherwise it will download the HTML page
    custom_feeds = [
        ("https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/main/latest.all.csv", "Tor ALL nodes") # URL, Feed Name
    ]
    feed_data.extend(custom_feeds)
    # --- END ADDITIONAL FEEDS ---    
    
    return feed_data

def create_log_file(log_file):
    """Creates the log file with headers."""
    with open(log_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Start Time", "Completion Time", "Total Run Time (seconds)", "Error Feeds"])

def write_log_entry(log_file, log_data):
    """Writes a log entry to the CSV file."""
    with open(log_file, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            log_data["date"],
            log_data["start_time"],
            log_data["completion_time"],
            log_data["total_time"],
            "; ".join(log_data["error_feeds"]),
        ])

def main():
    """Main function to run the script."""
    global successful_feed_count  # Access the global counter
    successful_feed_count = 0  # Reset counter at the start of each run

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    create_log_file(LOG_FILE)

    log_data = {
        "date": datetime.date.today().strftime("%Y-%m-%d"),
        "start_time": datetime.datetime.now().strftime("%H:%M:%S"),
        "completion_time": "",
        "total_time": 0,
        "error_feeds": [],
    }

    ascii_art()

    # User prompt to start download
    days_back_user_input = input(f"Enter number of days back to download feeds (default: {DAYS_BACK_DEFAULT}): ").strip()
    try:
        days_back = int(days_back_user_input) if days_back_user_input else DAYS_BACK_DEFAULT
        if days_back <= 0:
            days_back = DAYS_BACK_DEFAULT # Revert to default if invalid input
            print(f"Invalid input. Using default days back: {DAYS_BACK_DEFAULT} days.")
    except ValueError:
        days_back = DAYS_BACK_DEFAULT # Revert to default if not a number
        print(f"Invalid input. Using default days back: {DAYS_BACK_DEFAULT} days.")

    input(f"Press Enter to begin downloading MISP feeds for the past {days_back} days...")
    print(f"Downloading MISP default feeds for the past {days_back} days...")

    start_time = time.time()
    feed_data = fetch_feed_list()

    if not feed_data:
        print("No feeds found. Exiting.")
        return

    # Feed Categorization for Download Order
    feed_categories_ordered = [
        ("CIRCL Feeds", [(url, name) for url, name in feed_data if is_circl_feed_url(url)]),
        ("Botvrij Feeds", [(url, name) for url, name in feed_data if "botvrij" in name.lower()]),
        ("Malware Bazaar Feeds", [(url, name) for url, name in feed_data if is_malwarebazaar_feed_url(url)]),
        ("ThreatFox Feeds", [(url, name) for url, name in feed_data if is_threatfox_feed_url(url)]),
        ("URLHaus Feeds", [(url, name) for url, name in feed_data if is_urlhaus_feed_url(url)]),
        ("TweetFeed Feeds", [(url, name) for url, name in feed_data if is_tweetfeed_url(url)]),
        ("MISP Site Feeds (Others)", [(url, name) for url, name in feed_data if not any([is_circl_feed_url(url), "botvrij" in name.lower(), is_malwarebazaar_feed_url(url), is_threatfox_feed_url(url), is_urlhaus_feed_url(url), is_tweetfeed_url(url)])]),
    ]

    for category_name, feeds in feed_categories_ordered:
        if feeds: # Only process if there are feeds in this category
            print(f"\n--- Processing Category: {category_name} ---")
            print(f"Downloading feeds for category: {category_name}") # Informative message - category start
            total_tasks = len(feeds)
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(process_single_feed, url, name, OUTPUT_DIR, log_data, days_back) for url, name in feeds]
                for future in futures: # Removed tqdm progress bar - direct iteration
                    future.result() # Still need to get result to ensure tasks complete
        else:
            print(f"\n--- No feeds in Category: {category_name} ---")

    end_time = time.time()
    log_data["completion_time"] = datetime.datetime.now().strftime("%H:%M:%S")
    log_data["total_time"] = round(end_time - start_time, 2)
    write_log_entry(LOG_FILE, log_data)

    # Completion message
    print(f"\n--- Script Completed ---")
    print(f"Total feeds processed: {len(feed_data)}")
    print(f"Feeds downloaded successfully: {successful_feed_count}")
    if log_data["error_feeds"]:
        print(f"Feeds with errors (see log file for details): {len(log_data['error_feeds'])}")
    else:
        print("No feeds had errors during download.")
    print(f"Log file: {LOG_FILE}")

if __name__ == "__main__":
    main()
