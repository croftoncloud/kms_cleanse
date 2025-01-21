'''
utils/config_loader.py
'''
import logging
import yaml

logger = logging.getLogger(__name__)

def load_config(file_path="config.yaml"):
    '''
    Load a YAML configuration file.

    Args:
        file_path (str): Path to the YAML configuration file

    Returns:
        dict: Configuration settings
    '''
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.error("Configuration file '%s' not found.", file_path)
        return {}
    except yaml.YAMLError as e:
        logger.error("Error parsing configuration file: %s", e)
        return {}
