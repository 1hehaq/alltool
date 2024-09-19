import argparse
import json
import subprocess
import sys

class BugBountyTool:
    def __init__(self, config_file='config.json'):
        self.config = self.load_config(config_file)

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Config file '{config_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in config file '{config_file}'.")
            sys.exit(1)

    def run_tool(self, tool_name, args):
        if tool_name not in self.config:
            print(f"Error: Tool '{tool_name}' not found in config.")
            return

        tool_config = self.config[tool_name]
        command = [tool_config['command']] + tool_config.get('default_args', []) + args

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error running {tool_name}: {e}")
            print(e.stderr)

def main():
    parser = argparse.ArgumentParser(description="All-in-One Bug Bounty Tool")
    parser.add_argument('tool', help="Name of the tool to run")
    parser.add_argument('args', nargs=argparse.REMAINDER, help="Arguments to pass to the tool")

    args = parser.parse_args()

    bug_bounty_tool = BugBountyTool()
    bug_bounty_tool.run_tool(args.tool, args.args)

if __name__ == "__main__":
    main()
