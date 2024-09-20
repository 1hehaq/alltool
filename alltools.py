import argparse
import json
import subprocess
import sys
import os
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Union, Tuple
import re
import requests
import shutil
from colorama import Fore, Back, Style, init
from halo import Halo
import pyfiglet
import textwrap
import random
import sys
import traceback
import urllib.parse
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import tldextract
import os
import json
import requests
from packaging import version
from halo import Halo
import signal
import threading
import sys

# Global flag to signal threads to stop
stop_scan = threading.Event()

def signal_handler(signum, frame):
    if not stop_scan.is_set():
        stop_scan.set()
        print(f"\n{Fore.YELLOW}Scan interrupted by user. Cleaning up...{Style.RESET_ALL}")
        sys.exit(0)

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'INFO': Fore.CYAN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE,
        'DEBUG': Fore.BLUE
    }

    def format(self, record):
        log_message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{log_message}{Style.RESET_ALL}"

# Remove all handlers associated with the root logger object
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# Add our custom handler
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(message)s'))
logger.addHandler(handler)

TIPS = [
    "Always keep your tools and systems updated!",
    "Remember to get proper authorization before scanning any target.",
    "Use a VPN for added anonymity during your scans.",
    "Regularly backup your findings and configurations.",
    "Combine multiple tools for more comprehensive results.",
    "Don't forget to verify your findings manually!",
    "Respect the scope of your engagement at all times.",
    "Learn to read and understand the raw output of your tools.",
    "Automate repetitive tasks to save time and reduce errors.",
    "Stay curious and keep learning about new vulnerabilities and techniques!"
]

class ColoredHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def _format_action_invocation(self, action):
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ', '.join(action.option_strings) + ' ' + args_string

    def _get_help_string(self, action):
        help = action.help
        if '%(default)' not in action.help:
            if action.default is not argparse.SUPPRESS:
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if action.option_strings or action.nargs in defaulting_nargs:
                    help += ' (default: %(default)s)'
        return help

    def _fill_text(self, text, width, indent):
        return ''.join(indent + line for line in text.splitlines(keepends=True))

    def _split_lines(self, text, width):
        return textwrap.wrap(text, width)

CURRENT_VERSION = "v2.0"
CONFIG_FILE = "config.json"

# Global variable to store the config path
config_path = CONFIG_FILE

def create_parser():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}alltools - All-in-One security scanning tool{Style.RESET_ALL}",
        formatter_class=ColoredHelpFormatter,
        add_help=False,
        epilog=textwrap.dedent(f'''
            {Fore.YELLOW}Examples:{Style.RESET_ALL}
              {Fore.GREEN}Subdomain Enumeration:{Style.RESET_ALL}
                python alltools.py subenum --target example.com --output subdomains.txt
              {Fore.GREEN}Port Scanning:{Style.RESET_ALL}
                python alltools.py portscan --target example.com --output open_ports.txt
              {Fore.GREEN}Probe Alive Domains:{Style.RESET_ALL}
                python alltools.py probe --target subdomains.txt --output alive_domains.txt
              {Fore.GREEN}Vulnerability Scanning:{Style.RESET_ALL}
                python alltools.py vulnscan --target example.com --type xss sqli --output vulnerabilities.json
              {Fore.GREEN}Web Crawling:{Style.RESET_ALL}
                python alltools.py crawler --target example.com --depth 3 --output crawl_results.json
              {Fore.GREEN}Parameter Fuzzing:{Style.RESET_ALL}
                python alltools.py paramfuzz --target example.com --output params.json

            {Fore.YELLOW}For more information on a specific command, use:{Style.RESET_ALL}
              python alltools.py <command> --help
        ''')
    )

    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help=f'{Fore.GREEN}Show this help message and exit{Style.RESET_ALL}')
    parser.add_argument('--update', action='store_true', help=f'{Fore.GREEN}Check for updates and install the latest version{Style.RESET_ALL}')
    parser.add_argument('--list-tools', action='store_true', help=f'{Fore.GREEN}List available tools for each task{Style.RESET_ALL}')
    parser.add_argument('--validate', action='store_true', help=f'{Fore.GREEN}Validate the configuration file{Style.RESET_ALL}')
    parser.add_argument('--config', help=f'{Fore.GREEN}Set a new configuration file path{Style.RESET_ALL}')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subdomain enumeration parser
    subenum_parser = subparsers.add_parser('subenum', help=f'{Fore.YELLOW}Perform subdomain enumeration{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                           description=textwrap.dedent(f'''
        {Fore.CYAN}Subdomain Enumeration{Style.RESET_ALL}
        This command performs subdomain enumeration using various tools and techniques.
        It helps discover subdomains associated with the target domain.
        '''),
                                           epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py subenum --target example.com
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py subenum --target example.com --output subdomains.txt
          {Fore.GREEN}Exclude specific tools:{Style.RESET_ALL}
            python alltools.py subenum --target example.com --exclude subfinder amass
        '''))
    subenum_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    subenum_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    subenum_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the enumeration process{Style.RESET_ALL}')

    # Port scanning parser
    portscan_parser = subparsers.add_parser('portscan', help=f'{Fore.YELLOW}Perform port scanning{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                            description=textwrap.dedent(f'''
        {Fore.CYAN}Port Scanning{Style.RESET_ALL}
        This command performs port scanning on the target hosts to identify open ports and services.
        It uses various port scanning tools to provide comprehensive results.
        '''),
                                            epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py portscan --target example.com
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py portscan --target example.com --output open_ports.txt
          {Fore.GREEN}Exclude specific tools:{Style.RESET_ALL}
            python alltools.py portscan --target example.com --exclude nmap masscan
        '''))
    portscan_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    portscan_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    portscan_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the port scanning process{Style.RESET_ALL}')

    # Probe parser
    probe_parser = subparsers.add_parser('probe', help=f'{Fore.YELLOW}Probe for alive domains{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                         description=textwrap.dedent(f'''
        {Fore.CYAN}Probe Alive Domains{Style.RESET_ALL}
        This command probes a list of domains to identify which ones are alive and responsive.
        It helps filter out inactive or non-existent domains from your target list.
        '''),
                                         epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py probe --target domains.txt
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py probe --target domains.txt --output alive_domains.txt
          {Fore.GREEN}Exclude specific tools:{Style.RESET_ALL}
            python alltools.py probe --target domains.txt --exclude httpx
        '''))
    probe_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    probe_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    probe_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the probing process{Style.RESET_ALL}')

    # Vulnerability scanning parser
    vulnscan_parser = subparsers.add_parser('vulnscan', help=f'{Fore.YELLOW}Perform vulnerability scanning{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                            description=textwrap.dedent(f'''
        {Fore.CYAN}Vulnerability Scanning{Style.RESET_ALL}
        This command performs vulnerability scanning on the target hosts to identify potential security weaknesses.
        It can scan for various types of vulnerabilities using different tools.
        '''),
                                            epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py vulnscan --target example.com
          {Fore.GREEN}Scan for specific vulnerability types:{Style.RESET_ALL}
            python alltools.py vulnscan --target example.com --type xss sqli
          {Fore.GREEN}Use specific tools:{Style.RESET_ALL}
            python alltools.py vulnscan --target example.com --tool nuclei
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py vulnscan --target example.com --output vulnerabilities.json
        '''))
    vulnscan_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--type', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Types of vulnerabilities to scan for (e.g., xss, sqli, ssrf){Style.RESET_ALL}')
    vulnscan_parser.add_argument('--tool', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Specific tools to use for vulnerability scanning{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--isolate', action='store_true', help=f'{Fore.LIGHTCYAN_EX}Run only one tool per vulnerability type{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the vulnerability scanning process{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')

    # Crawler parser
    crawler_parser = subparsers.add_parser('crawler', help=f'{Fore.YELLOW}Perform web crawling and directory enumeration{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                           description=textwrap.dedent(f'''
        {Fore.CYAN}Web Crawling and Directory Enumeration{Style.RESET_ALL}
        This command performs web crawling and directory enumeration on the target websites.
        It discovers URLs, directories, and files within the target domain.
        '''),
                                           epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py crawler --target example.com
          {Fore.GREEN}Set crawl depth:{Style.RESET_ALL}
            python alltools.py crawler --target example.com --depth 5
          {Fore.GREEN}Limit the number of URLs to crawl:{Style.RESET_ALL}
            python alltools.py crawler --target example.com --max-urls 1000
          {Fore.GREEN}Respect robots.txt rules:{Style.RESET_ALL}
            python alltools.py crawler --target example.com --respect-robots
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py crawler --target example.com --output crawl_results.json
        '''))
    crawler_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    crawler_parser.add_argument('--depth', type=int, default=3, help=f'{Fore.LIGHTCYAN_EX}Maximum crawl depth (default: 3){Style.RESET_ALL}')
    crawler_parser.add_argument('--max-urls', type=int, default=1000, help=f'{Fore.LIGHTCYAN_EX}Maximum number of URLs to crawl (default: 1000){Style.RESET_ALL}')
    crawler_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    crawler_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the crawling process{Style.RESET_ALL}')
    crawler_parser.add_argument('--respect-robots', action='store_true', help=f'{Fore.LIGHTCYAN_EX}Respect robots.txt rules{Style.RESET_ALL}')
    crawler_parser.add_argument('--headers', type=json.loads, help=f'{Fore.LIGHTCYAN_EX}Custom headers as JSON string{Style.RESET_ALL}')
    crawler_parser.add_argument('--extensions', nargs='+', help=f'{Fore.LIGHTCYAN_EX}File extensions to look for{Style.RESET_ALL}')
    crawler_parser.add_argument('--follow-subdomains', action='store_true', help=f'{Fore.LIGHTCYAN_EX}Follow links to subdomains{Style.RESET_ALL}')

    # Parameter fuzzing parser
    paramfuzz_parser = subparsers.add_parser('paramfuzz', help=f'{Fore.YELLOW}Perform parameter fuzzing{Style.RESET_ALL}', formatter_class=ColoredHelpFormatter,
                                             description=textwrap.dedent(f'''
        {Fore.CYAN}Parameter Fuzzing{Style.RESET_ALL}
        This command performs parameter fuzzing on the target URLs to discover hidden or undocumented parameters.
        It uses various tools to identify potential injection points and parameter names.
        '''),
                                             epilog=textwrap.dedent(f'''
        {Fore.YELLOW}Examples:{Style.RESET_ALL}
          {Fore.GREEN}Basic usage:{Style.RESET_ALL}
            python alltools.py paramfuzz --target https://example.com/page
          {Fore.GREEN}Use specific tools:{Style.RESET_ALL}
            python alltools.py paramfuzz --target https://example.com/page --tool arjun paramspider
          {Fore.GREEN}Exclude specific tools:{Style.RESET_ALL}
            python alltools.py paramfuzz --target https://example.com/page --exclude x8
          {Fore.GREEN}Save results to a file:{Style.RESET_ALL}
            python alltools.py paramfuzz --target https://example.com/page --output params.json
        '''))
    paramfuzz_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target URL or file with list of URLs{Style.RESET_ALL}')
    paramfuzz_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    paramfuzz_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude from the parameter fuzzing process{Style.RESET_ALL}')
    paramfuzz_parser.add_argument('--tool', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Specific tools to use for parameter fuzzing{Style.RESET_ALL}')

    return parser

def gradient_print(text, start_color, end_color):
    for i, char in enumerate(text):
        r = int(start_color[0] + (end_color[0] - start_color[0]) * i / len(text))
        g = int(start_color[1] + (end_color[1] - start_color[1]) * i / len(text))
        b = int(start_color[2] + (end_color[2] - start_color[2]) * i / len(text))
        print(f"\033[38;2;{r};{g};{b}m{char}", end="")
    print(Style.RESET_ALL)

def print_banner():
    banner = pyfiglet.figlet_format("alltools", font="slant")
    gradient_print(banner, (0, 255, 255), (255, 0, 255))
    
    version_status = get_version_status()
    logger.info(f"{Fore.LIGHTGREEN_EX}All-in-One Security Scanner Created by - {Style.RESET_ALL}"
                f"\033]8;;https://github.com/1hehaq\033\\{Fore.LIGHTRED_EX}@1hehaq\033]8;;\033\\ {Style.RESET_ALL}")
    logger.info("")
    logger.info(f"{Fore.CYAN}Using config file:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{config_path}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}Current alltools version:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{CURRENT_VERSION}{Style.RESET_ALL} ({version_status})")
    logger.info("")

    tip = random.choice(TIPS)
    wrapped_tip = textwrap.wrap(tip, width=60)
    max_length = max(len(line) for line in wrapped_tip)
    
    logger.info(f"{Fore.YELLOW}┌─ Tip of the Day {'─' * (max_length - 15)}┐{Style.RESET_ALL}")
    for line in wrapped_tip:
        logger.info(f"{Fore.YELLOW}│ {Fore.CYAN}{line:<{max_length}} {Fore.YELLOW}│{Style.RESET_ALL}")
    logger.info(f"{Fore.YELLOW}└{'─' * (max_length + 2)}┘{Style.RESET_ALL}\n")



def print_completion_banner(results):
    logger.info(f"{Fore.YELLOW}Summary of findings:{Style.RESET_ALL}")
    for key, value in results.items():
        if isinstance(value, list):
            logger.info(f"{Fore.CYAN}{key.capitalize()}: {Fore.WHITE}{len(value)} found")
        elif isinstance(value, dict):
            logger.info(f"{Fore.CYAN}{key.capitalize()}:")
            for subkey, subvalue in value.items():
                logger.info(f"  {Fore.LIGHTCYAN_EX}{subkey}: {Fore.WHITE}{len(subvalue) if isinstance(subvalue, list) else subvalue} found")
    logger.info(f"\n{Fore.YELLOW}Detailed results are stored in the 'results' attribute of the scanner object.{Style.RESET_ALL}")

# Custom Exceptions
class AllToolsError(Exception):
    """Base exception for AllTools"""
    pass

class ConfigurationError(AllToolsError):
    """Raised when there's an issue with the configuration"""
    pass

class ToolExecutionError(AllToolsError):
    """Raised when a tool fails to execute properly"""
    pass

class InputError(AllToolsError):
    """Raised when there's an issue with user input"""
    pass

# Global Error Handler
def global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("An unexpected error occurred:", exc_info=(exc_type, exc_value, exc_traceback))
    logger.error(f"\n{Fore.RED}An unexpected error occurred. Please check the log file for details.{Style.RESET_ALL}")

sys.excepthook = global_exception_handler

from halo import Halo
import sys

class NonInterferenceSpinner(Halo):
    def start(self, text=None):
        if sys.stdout.isatty():
            super().start(text)

    def stop(self):
        if sys.stdout.isatty():
            super().stop()

spinner = NonInterferenceSpinner(spinner='dots')

# Enhance the SecurityScanner class
class SecurityScanner:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.results: Dict[str, Any] = {}
        self.stop_scan = stop_scan  # Add reference to the global stop_scan event

    def load_config(self, config_file: str) -> Dict[str, Any]:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.validate_config(config)
            return config
        except FileNotFoundError:
            raise ConfigurationError(f"Config file '{config_file}' not found.")
        except json.JSONDecodeError:
            raise ConfigurationError(f"Invalid JSON in config file '{config_file}'.")

    def validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = ['subdomain_enum', 'port_scan', 'probe', 'vuln_scan', 'crawler', 'paramfuzz']
        for key in required_keys:
            if key not in config:
                raise ConfigurationError(f"Missing required key '{key}' in config.")
            if not isinstance(config[key], dict):
                raise ConfigurationError(f"Invalid configuration for '{key}'. Expected a dictionary.")

    def run_command(self, command: List[str], silent: bool = False, timeout: int = 300) -> str:
        try:
            if not shutil.which(command[0]):
                raise ToolExecutionError(f"Tool '{command[0]}' not found. Please install it or add it to your PATH.")
            
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Error running command {' '.join(command)}: {e}"
            if not silent:
                logger.error(error_msg)
            raise ToolExecutionError(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"Command {' '.join(command)} timed out after {timeout} seconds"
            if not silent:
                logger.error(error_msg)
            raise ToolExecutionError(error_msg)

    def run_tool(self, tool, command, target):
        if self.stop_scan.is_set():
            return tool, target, set(), "interrupted", "Scan interrupted by user"
        
        try:
            if tool == "oneliners":
                formatted_command = command.format(target=target)
                output = subprocess.run(formatted_command, shell=True, capture_output=True, text=True, check=True)
            else:
                if not shutil.which(command[0]):
                    return tool, target, set(), "error", f"Tool '{command[0]}' not found. Please install it or add it to your PATH."

                formatted_command = [arg.format(target=target) for arg in command]
                output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)

            subdomain_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
            subdomains = set(subdomain_pattern.findall(output.stdout))
            target_subdomains = {subdomain for subdomain in subdomains if subdomain.endswith(target)}

            if not target_subdomains:
                return tool, target, set(), "not_found", "No subdomains found."

            return tool, target, target_subdomains, "success", None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command '{formatted_command if isinstance(formatted_command, str) else ' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."
            return tool, target, set(), "error", error_msg

    def subdomain_enumeration(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing Subdomain Enumeration{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        all_subdomains = set()

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for target in targets:
                    for tool, command in self.config['subdomain_enum'].items():
                        if args.exclude and tool in args.exclude:
                            continue
                        if tool == "oneliners":
                            for oneliner in command:
                                futures.append(executor.submit(self.run_tool, "oneliners", oneliner, target))
                        else:
                            futures.append(executor.submit(self.run_tool, tool, command, target))

                for future in as_completed(futures):
                    if self.stop_scan.is_set():
                        break

                    tool, target, subdomains, status, message = future.result()
                    spinner.stop()

                    if status == "error":
                        logger.error(f"{Fore.LIGHTRED_EX}✖ Error running {tool} for {target}: {message}{Style.RESET_ALL}")
                    elif status == "not_found":
                        logger.warning(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {Fore.CYAN}{tool} found no subdomains for {target}{Style.RESET_ALL}")
                    elif status == "interrupted":
                        logger.info(f"{Fore.LIGHTYELLOW_EX}Scan interrupted: {tool} for {target}{Style.RESET_ALL}")
                        break
                    else:
                        all_subdomains.update(subdomains)
                        logger.info(f"{Fore.LIGHTGREEN_EX}✓{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{tool} found {len(subdomains)} subdomains for {target}{Style.RESET_ALL}")
                        for subdomain in sorted(subdomains):
                            logger.info(f"  {Fore.LIGHTYELLOW_EX}{subdomain}{Style.RESET_ALL}")
                
                    spinner.text = f"{Fore.CYAN}Performing Subdomain Enumeration{Style.RESET_ALL}"
                    spinner.start()

        except KeyboardInterrupt:
            pass
        finally:
            spinner.stop()
            if self.stop_scan.is_set():
                return

        if self.stop_scan.is_set():
            logger.info(f"{Fore.YELLOW}Subdomain enumeration interrupted by user{Style.RESET_ALL}")
        elif all_subdomains:
            logger.info(f"{Fore.LIGHTGREEN_EX}Total unique subdomains found: {len(all_subdomains)}{Style.RESET_ALL}")
        else:
            logger.warning(f"{Fore.LIGHTYELLOW_EX}No subdomains found for any targets{Style.RESET_ALL}")

        self.results['subdomains'] = list(all_subdomains)

        if args.output:
            with open(args.output, 'w') as f:
                for subdomain in sorted(all_subdomains):
                    f.write(f"{subdomain}\n")
            logger.info(f"Subdomains saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Subdomain Enumeration Complete{Style.RESET_ALL}")

    def get_timestamp(self) -> str:
        return f"{Fore.LIGHTMAGENTA_EX}[{time.strftime('%H:%M:%S')}]{Style.RESET_ALL}"

    def port_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing Port Scanning{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        all_open_ports = {}

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for target in targets:
                    for tool, command in self.config['port_scan'].items():
                        if args.exclude and tool in args.exclude:
                            continue
                        futures.append(executor.submit(self.run_tool, tool, command, target))

                for future in as_completed(futures):
                    if self.stop_scan.is_set():
                        break

                    tool, target, open_ports, status, message = future.result()
                    spinner.stop()

                    if status == "error":
                        logger.error(f"{Fore.LIGHTRED_EX}✖ Error running {tool} for {target}: {message}{Style.RESET_ALL}")
                    elif status == "not_found":
                        logger.warning(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {Fore.CYAN}{tool} found no open ports for {target}{Style.RESET_ALL}")
                    elif status == "interrupted":
                        logger.info(f"{Fore.LIGHTYELLOW_EX}Scan interrupted: {tool} for {target}{Style.RESET_ALL}")
                        break
                    else:
                        if target not in all_open_ports:
                            all_open_ports[target] = set()
                        all_open_ports[target].update(open_ports)
                        logger.info(f"{Fore.LIGHTGREEN_EX}✓{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{tool} found {len(open_ports)} open ports for {target}{Style.RESET_ALL}")
                        for port in sorted(open_ports):
                            logger.info(f"  {Fore.LIGHTYELLOW_EX}Port {port}{Style.RESET_ALL}")
                
                    spinner.text = f"{Fore.CYAN}Performing Port Scanning{Style.RESET_ALL}"
                    spinner.start()

        except KeyboardInterrupt:
            pass
        finally:
            spinner.stop()
            if self.stop_scan.is_set():
                return

        if self.stop_scan.is_set():
            logger.info(f"{Fore.YELLOW}Port scanning interrupted by user{Style.RESET_ALL}")
        elif all_open_ports:
            logger.info(f"{Fore.LIGHTGREEN_EX}Total targets scanned: {len(all_open_ports)}{Style.RESET_ALL}")
            for target, ports in all_open_ports.items():
                logger.info(f"{Fore.LIGHTCYAN_EX}{target}: {len(ports)} open ports{Style.RESET_ALL}")
        else:
            logger.warning(f"{Fore.LIGHTYELLOW_EX}No open ports found for any targets{Style.RESET_ALL}")

        self.results['open_ports'] = all_open_ports

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_open_ports, f, indent=2)
            logger.info(f"Open ports saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Port Scanning Complete{Style.RESET_ALL}")

    def probe_alive_domains(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Probing for alive domains{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        alive_domains = set()

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for tool, command in self.config['probe'].items():
                    if args.exclude and tool in args.exclude:
                        continue
                    futures.append(executor.submit(self.run_tool, tool, command, targets))

                for future in as_completed(futures):
                    if self.stop_scan.is_set():
                        break

                    tool, _, domains, status, message = future.result()
                    spinner.stop()

                    if status == "error":
                        logger.error(f"{Fore.LIGHTRED_EX}✖ Error running {tool}: {message}{Style.RESET_ALL}")
                    elif status == "not_found":
                        logger.warning(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {Fore.CYAN}{tool} found no alive domains{Style.RESET_ALL}")
                    elif status == "interrupted":
                        logger.info(f"{Fore.LIGHTYELLOW_EX}Scan interrupted: {tool}{Style.RESET_ALL}")
                        break
                    else:
                        alive_domains.update(domains)
                        logger.info(f"{Fore.LIGHTGREEN_EX}✓{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{tool} found {len(domains)} alive domains{Style.RESET_ALL}")
                        for domain in sorted(domains):
                            logger.info(f"  {Fore.LIGHTYELLOW_EX}{domain}{Style.RESET_ALL}")
                
                    spinner.text = f"{Fore.CYAN}Probing for alive domains{Style.RESET_ALL}"
                    spinner.start()

        except KeyboardInterrupt:
            pass
        finally:
            spinner.stop()
            if self.stop_scan.is_set():
                return

        if self.stop_scan.is_set():
            logger.info(f"{Fore.YELLOW}Probing interrupted by user{Style.RESET_ALL}")
        elif alive_domains:
            logger.info(f"{Fore.LIGHTGREEN_EX}Total alive domains found: {len(alive_domains)}{Style.RESET_ALL}")
        else:
            logger.warning(f"{Fore.LIGHTYELLOW_EX}No alive domains found{Style.RESET_ALL}")

        self.results['alive_domains'] = list(alive_domains)

        if args.output:
            with open(args.output, 'w') as f:
                for domain in sorted(alive_domains):
                    f.write(f"{domain}\n")
            logger.info(f"Alive domains saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Probing Complete{Style.RESET_ALL}")

    def vulnerability_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing Vulnerability Scanning{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        vulnerabilities = []

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for tool, command in self.config['vuln_scan'].items():
                    if args.exclude and tool in args.exclude:
                        continue
                    for target in targets:
                        futures.append(executor.submit(self.run_tool, tool, command, target))

                for future in as_completed(futures):
                    if self.stop_scan.is_set():
                        break

                    tool, target, vulns, status, message = future.result()
                    spinner.stop()

                    if status == "error":
                        logger.error(f"{Fore.LIGHTRED_EX}✖ Error running {tool} for {target}: {message}{Style.RESET_ALL}")
                    elif status == "not_found":
                        logger.warning(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {Fore.CYAN}{tool} found no vulnerabilities for {target}{Style.RESET_ALL}")
                    elif status == "interrupted":
                        logger.info(f"{Fore.LIGHTYELLOW_EX}Scan interrupted: {tool} for {target}{Style.RESET_ALL}")
                        break
                    else:
                        vulnerabilities.extend(vulns)
                        logger.info(f"{Fore.LIGHTGREEN_EX}✓{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{tool} found {len(vulns)} vulnerabilities for {target}{Style.RESET_ALL}")
                        for vuln in vulns:
                            logger.info(f"  {Fore.LIGHTYELLOW_EX}{vuln['type']} - {vuln['description']}{Style.RESET_ALL}")
                
                    spinner.text = f"{Fore.CYAN}Performing Vulnerability Scanning{Style.RESET_ALL}"
                    spinner.start()

        except KeyboardInterrupt:
            pass
        finally:
            spinner.stop()
            if self.stop_scan.is_set():
                return

        if self.stop_scan.is_set():
            logger.info(f"{Fore.YELLOW}Vulnerability scanning interrupted by user{Style.RESET_ALL}")
        elif vulnerabilities:
            logger.info(f"{Fore.LIGHTGREEN_EX}Total vulnerabilities found: {len(vulnerabilities)}{Style.RESET_ALL}")
        else:
            logger.warning(f"{Fore.LIGHTYELLOW_EX}No vulnerabilities found for any targets{Style.RESET_ALL}")

        self.results['vulnerabilities'] = vulnerabilities

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            logger.info(f"Vulnerabilities saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Vulnerability Scanning Complete{Style.RESET_ALL}")

    def parse_vulnerability_output(self, tool: str, output: str) -> List[Dict[str, str]]:
        # Implement parsing logic for different vulnerability scanning tools
        # This is a simplified example
        vulnerabilities = []
        for line in output.splitlines():
            if 'vulnerability' in line.lower():
                vuln = {
                    'type': 'Unknown',
                    'severity': 'Unknown',
                    'description': line.strip()
                }
                vulnerabilities.append(vuln)
        return vulnerabilities

    async def crawler(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing Web Crawling{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        logger.info(f"{self.get_timestamp()} Starting web crawling...")

        results = []
        async with aiohttp.ClientSession() as session:
            for target in targets:
                crawler = Crawler(self.config, args.depth, args.max_urls, args.respect_robots, 
                                  args.headers, args.extensions, args.follow_subdomains)
                crawl_results = await crawler.crawl(target, session)
                results.extend(crawl_results)

        spinner.succeed(f"{Fore.GREEN}Web crawling completed{Style.RESET_ALL}")
        self.results['crawler'] = results
        if args.output:
            self.save_results(args.output, results)

    def display_sample_results(self, result: Dict[str, Any], sample_size: int = 5):
        logger.info(f"  {Fore.LIGHTYELLOW_EX}Sample URLs:{Style.RESET_ALL}")
        for url in list(result['urls'])[:sample_size]:
            logger.info(f"    {Fore.LIGHTYELLOW_EX}{url}{Style.RESET_ALL}")

        logger.info(f"  {Fore.LIGHTYELLOW_EX}Sample Directories:{Style.RESET_ALL}")
        for directory in list(result['directories'])[:sample_size]:
            logger.info(f"    {Fore.LIGHTYELLOW_EX}{directory}{Style.RESET_ALL}")

        logger.info(f"  {Fore.LIGHTYELLOW_EX}Sample Files:{Style.RESET_ALL}")
        for ext, files in result['files'].items():
            logger.info(f"    {Fore.LIGHTYELLOW_EX}{ext}:{Style.RESET_ALL}")
            for file in list(files)[:3]:
                logger.info(f"      {Fore.LIGHTYELLOW_EX}{file}{Style.RESET_ALL}")

    async def paramfuzz(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing Parameter Fuzzing{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        logger.info(f"{self.get_timestamp()} Starting parameter fuzzing...")

        wordlist = self.load_wordlist(args.wordlist)
        results = []

        async with aiohttp.ClientSession() as session:
            for target in targets:
                chunks = [wordlist[i:i+args.chunks] for i in range(0, len(wordlist), args.chunks)]
                for chunk in chunks:
                    tasks = []
                    for param in chunk:
                        url = f"{target}?{param}=FUZZ"
                        task = asyncio.create_task(self.fuzz_request(session, url, args))
                        tasks.append(task)
                    chunk_results = await asyncio.gather(*tasks)
                    results.extend(chunk_results)
                    await asyncio.sleep(args.delay)

        spinner.succeed(f"{Fore.GREEN}Parameter fuzzing completed{Style.RESET_ALL}")
        self.results['paramfuzz'] = results
        if args.output:
            self.save_results(args.output, results)

    def parse_paramfuzz_output(self, tool: str, output: str, target: str) -> List[Dict[str, Any]]:
        params = []
        if tool == "arjun":
            try:
                json_output = json.loads(output)
                for param in json_output.get(target, []):
                    params.append({"name": param, "type": "unknown"})
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Arjun JSON output for {target}")
        elif tool == "x8":
            for line in output.splitlines():
                if "=" in line:
                    param = line.split("=")[0].strip()
                    params.append({"name": param, "type": "unknown"})
        elif tool == "paramspider":
            with open(f"output_{target}.txt", "r") as f:
                for line in f:
                    parsed_url = urlparse(line.strip())
                    query_params = parse_qs(parsed_url.query)
                    for param in query_params:
                        params.append({"name": param, "type": "unknown"})
        elif tool == "param-miner":
            for line in output.splitlines():
                if "Found" in line and "=" in line:
                    param = line.split("=")[0].split()[-1].strip()
                    params.append({"name": param, "type": "unknown"})
        elif tool == "unfurl":
            for line in output.splitlines():
                params.append({"name": line.strip(), "type": "unknown"})

        return params

    def display_sample_params(self, params: List[Dict[str, Any]], sample_size: int = 5):
        logger.info(f"  {Fore.LIGHTYELLOW_EX}Sample Parameters:{Style.RESET_ALL}")
        for param in params[:sample_size]:
            logger.info(f"    {Fore.LIGHTYELLOW_EX}{param['name']} (Type: {param['type']}){Style.RESET_ALL}")
        if len(params) > sample_size:
            logger.info(f"    {Fore.LIGHTYELLOW_EX}... and {len(params) - sample_size} more{Style.RESET_ALL}")

    async def jsscrap(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner = Halo(text=f"{Fore.CYAN}Performing JavaScript Scraping{Style.RESET_ALL}", spinner="dots")
        spinner.start()
        logger.info(f"{self.get_timestamp()} Starting JavaScript scraping...")

        config = self.load_jsscrap_config(args.config_path)
        results = []

        async with aiohttp.ClientSession() as session:
            for target in targets:
                js_scraper = JsScraper(config, args.concurrency, args.delay)
                scrap_results = await js_scraper.scrap(target, session)
                results.extend(scrap_results)

        spinner.succeed(f"{Fore.GREEN}JavaScript scraping completed{Style.RESET_ALL}")
        self.results['jsscrap'] = results
        if args.output:
            self.save_results(args.output, results)

def check_for_updates():
    spinner = Halo(text='Checking for updates...', spinner='dots')
    spinner.start()
    try:
        response = requests.get('https://api.github.com/repos/1hehaq/alltools/releases/latest')
        latest_version = response.json()['tag_name']
        if version.parse(latest_version) > version.parse(CURRENT_VERSION):
            spinner.succeed(f"{Fore.YELLOW}New version available: {latest_version}{Style.RESET_ALL}")
            spinner.start('Updating...')
            # Add update logic here
            spinner.succeed(f"{Fore.GREEN}Updated to version {latest_version}{Style.RESET_ALL}")
        else:
            spinner.succeed(f"{Fore.GREEN}You are using the latest version: {CURRENT_VERSION}{Style.RESET_ALL}")
    except Exception as e:
        spinner.fail(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")

def get_version_status():
    try:
        response = requests.get('https://api.github.com/repos/1hehaq/alltools/releases/latest')
        latest_version = response.json()['tag_name']
        if version.parse(latest_version) > version.parse(CURRENT_VERSION):
            return f"{Fore.RED}oldest{Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}latest{Style.RESET_ALL}"

    except:
        return f"{Fore.YELLOW}unknown{Style.RESET_ALL}"

def list_tools(config):
    print(f"\n{Fore.CYAN}Available tools for each task:{Style.RESET_ALL}")
    for task, tools in config.items():
        print(f"\n{Fore.YELLOW}{task.capitalize()}:{Style.RESET_ALL}")
        for tool in tools:
            print(f"  {Fore.GREEN}- {tool}{Style.RESET_ALL}")

def validate_config(config_file):
    spinner = Halo(text='Validating configuration...', spinner='dots')
    spinner.start()
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        required_tasks = ['subdomain_enum', 'port_scan', 'probe', 'vuln_scan', 'crawler']
        for task in required_tasks:
            if task not in config:
                raise ConfigurationError(f"Missing required task: {task}")
            if not isinstance(config[task], dict):
                raise ConfigurationError(f"Invalid configuration for task: {task}")
        spinner.succeed(f"{Fore.GREEN}Configuration is valid{Style.RESET_ALL}")
    except FileNotFoundError:
        spinner.fail(f"{Fore.RED}Configuration file not found: {config_file}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        spinner.fail(f"{Fore.RED}Invalid JSON in configuration file: {config_file}{Style.RESET_ALL}")
    except ConfigurationError as e:
        spinner.fail(f"{Fore.RED}Configuration error: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        spinner.fail(f"{Fore.RED}Unexpected error during validation: {str(e)}{Style.RESET_ALL}")

def set_config_path(new_path):
    global config_path
    config_path = new_path
    print(f"{Fore.GREEN}Configuration file path updated to: {new_path}{Style.RESET_ALL}")

def main():
    parser = create_parser()
    args = parser.parse_args()

    print_banner()

    # Register the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    if args.update:
        check_for_updates()
        return

    if args.config:
        set_config_path(args.config)
        return

    if args.list_tools:
        with open(config_path, 'r') as f:
            config = json.load(f)
        list_tools(config)
        return

    if args.validate:
        validate_config(config_path)
        return

    if not args.command:
        parser.print_help()
        return

    try:
        scanner = SecurityScanner(config_path)

        targets = []
        if hasattr(args, 'target'):
            if os.path.isfile(args.target):
                with open(args.target, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            else:
                targets = [args.target]

        scan_performed = False
        if args.command == 'subenum':
            scanner.subdomain_enumeration(targets, args)
            scan_performed = True
        elif args.command == 'portscan':
            scanner.port_scanning(targets, args)
            scan_performed = True
        elif args.command == 'probe':
            scanner.probe_alive_domains(targets, args)
            scan_performed = True
        elif args.command == 'vulnscan':
            scanner.vulnerability_scanning(targets, args)
            scan_performed = True
        elif args.command == 'crawler':
            asyncio.run(scanner.crawler(targets, args))
            scan_performed = True
        elif args.command == 'paramfuzz':
            asyncio.run(scanner.paramfuzz(targets, args))
            scan_performed = True
        elif args.command == 'jsscrap':
            asyncio.run(scanner.jsscrap(targets, args))
            scan_performed = True

        if scan_performed and not stop_scan.is_set():
            print_completion_banner(scanner.results)

    except AllToolsError as e:
        logger.error(f"{Fore.RED}{type(e).__name__}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        logger.debug("", exc_info=True)

if __name__ == "__main__":
    main()
