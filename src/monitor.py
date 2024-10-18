import asyncio
import time
import logging
from contextlib import asynccontextmanager
from bpf_manager import BPFManager
from rule_engine import RuleEngine
from config_manager import ConfigManager

class Monitor:
    def __init__(self, config_file='config.yaml', learning_duration=30):
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.config
        self.rule_engine = RuleEngine(self.config)
        self.learning_duration = learning_duration
        self.logger = logging.getLogger(__name__)

    @asynccontextmanager
    async def bpf_manager_context(self):
        bpf_manager = BPFManager()
        try:
            await bpf_manager.load_all_programs()  # Await the load_all_programs method
            yield bpf_manager
        finally:
            if hasattr(bpf_manager, 'unload_all'):
                unload_method = bpf_manager.unload_all
                if asyncio.iscoroutinefunction(unload_method):
                    await unload_method()
                else:
                    unload_method()

    async def process_events(self, bpf_manager, is_learning_mode):
        async for event, detected_value in bpf_manager.monitor_events():
            if is_learning_mode:
                self.rule_engine.add_allowed_value(event, detected_value)
            elif not self.rule_engine.is_value_allowed(event, detected_value):
                await self.handle_violation(event, detected_value)

    async def start_learning_mode(self):
        self.logger.info(f"Learning mode: Monitoring for {self.learning_duration} seconds...")
        async with self.bpf_manager_context() as bpf_manager:
            try:
                await asyncio.wait_for(self.process_events(bpf_manager, True), timeout=self.learning_duration)
            except asyncio.TimeoutError:
                self.logger.info("Learning complete. Moving to alert/block mode.")
            finally:
                self.config['learning_mode'] = False
                self.config_manager.config = self.config
                self.config_manager.save_config()

    async def start_alert_or_block_mode(self):
        self.logger.info("Alert/Block mode: Monitoring for violations...")
        async with self.bpf_manager_context() as bpf_manager:
            await self.process_events(bpf_manager, False)

    async def handle_violation(self, event, detected_value):
        self.logger.warning(f"ALERT: {event} violation detected with value: {detected_value}")
        # Implement blocking logic if needed

    async def run(self):
        if self.config.get('learning_mode', True):
            await self.start_learning_mode()
        
        # This line should be outside the if statement to ensure it always runs
        await self.start_alert_or_block_mode()
