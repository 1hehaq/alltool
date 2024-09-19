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

    def run_task(self, task_name, tool_name=None, args=[]):
        if task_name not in self.config:
            print(f"Error: Task '{task_name}' not found in config.")
            return

        task_config = self.config[task_name]
        
        if tool_name is None:
            tool_name = task_config.get('default_tool')
        
        if tool_name not in task_config['tools']:
            print(f"Error: Tool '{tool_name}' not found for task '{task_name}'.")
            return

        tool_config = task_config['tools'][tool_name]
        command = [tool_config['command']] + tool_config.get('default_args', []) + args

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error running {tool_name} for task {task_name}: {e}")
            print(e.stderr)

    def list_tasks(self):
        print("Available tasks:")
        for task in self.config:
            print(f"- {task}")
            for tool in self.config[task]['tools']:
                print(f"  - {tool}")

def main():
    parser = argparse.ArgumentParser(description="All-in-One Bug Bounty Tool")
    parser.add_argument('task', help="Name of the task to run")
    parser.add_argument('--tool', help="Specific tool to use for the task")
    parser.add_argument('--list-tasks', action='store_true', help="List available tasks and tools")
    parser.add_argument('args', nargs=argparse.REMAINDER, help="Arguments to pass to the tool")

    args = parser.parse_args()

    bug_bounty_tool = BugBountyTool()

    if args.list_tasks:
        bug_bounty_tool.list_tasks()
    else:
        bug_bounty_tool.run_task(args.task, args.tool, args.args)

if __name__ == "__main__":
    main()
