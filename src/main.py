import argparse
import logging
from contextlib import contextmanager
from rule_engine import RuleEngine
from config_manager import ConfigManager
from monitor import Monitor
import asyncio

@contextmanager
def config_manager_context(config_file='config.yaml'):
    config_manager = ConfigManager(config_file)
    try:
        yield config_manager
    finally:
        config_manager.save_config()

def setup_logging(verbose):
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

async def run_monitor(monitor, args):
    if args.learning:
        logging.info("Learning mode enabled")
        await monitor.start_learning_mode()
    else:
        logging.info("Alert/Block mode enabled")
        await monitor.start_alert_or_block_mode()

def main():
    parser = argparse.ArgumentParser(description="eBPF Security Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--learning", action="store_true", help="Run the tool in learning mode")
    group.add_argument("--alert", action="store_true", help="Run the tool in alert/block mode")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    setup_logging(args.verbose)

    config_manager = ConfigManager('config.yaml')
    config = config_manager.load_config()
    rule_engine = RuleEngine(config)
    monitor = Monitor(config_file='config.yaml', learning_duration=30)

    asyncio.run(run_monitor(monitor, args))

    # Update the config in ConfigManager and save it
    config_manager.config = monitor.rule_engine.config
    config_manager.save_config()

if __name__ == "__main__":
    main()
