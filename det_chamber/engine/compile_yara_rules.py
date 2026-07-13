import yara
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import subprocess
import argparse

# Configure logging
log_dir = Path("C:\\Logs")
log_dir.mkdir(exist_ok=True)
handler = RotatingFileHandler(log_dir / "yara_compile.log", maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler()])
logger = logging.getLogger(__name__)

def validate_yara_syntax(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            yara.compile(source=f.read(), error_on_warning=False)
        return True
    except yara.SyntaxError as e:
        logger.error(f"YARA syntax error in {filepath}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error validating {filepath}: {e}")
        return False

def compile_yara_rules(source_dir="E:\\YARA\\Rules", output_file="E:\\YARA\\windows_x64_rules.yar", ps_script="E:\\app\\filter_yara_rules.ps1"):
    try:
        # Run PowerShell script to filter rules
        subprocess.run(["powershell", "-File", ps_script, "-SourceDir", source_dir, "-OutputFile", output_file], check=True)
        logger.info(f"Filtered YARA rules to {output_file}")

        # Validate YARA syntax
        if not validate_yara_syntax(output_file):
            raise ValueError(f"Invalid YARA syntax in {output_file}")

        # Optimize YARA compilation
        yara.set_config(stack_size=65536, max_strings_per_rule=20000, max_match_data=1024)

        # Compile rules
        rules = yara.compile(filepath=output_file, error_on_warning=False)
        rules.save(output_file.replace(".yar", ".compiled"))
        logger.info(f"Compiled YARA rules to {output_file.replace('.yar', '.compiled')}")
        return rules
    except Exception as e:
        logger.error(f"Error compiling YARA rules: {e}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compile YARA rules for Windows x64")
    parser.add_argument("--source-dir", default="E:\\YARA\\Rules", help="YARA rules directory")
    parser.add_argument("--output-file", default="E:\\YARA\\windows_x64_rules.yar", help="Output YARA file")
    parser.add_argument("--ps-script", default="E:\\app\\filter_yara_rules.ps1", help="PowerShell filter script")
    args = parser.parse_args()
    compile_yara_rules(args.source_dir, args.output_file, args.ps_script)