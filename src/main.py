#!/usr/bin/env python3

"""
Script to run the Gas Optimization detector on Solidity contracts.
Usage: python run_gas_detector.py <solidity_file>
"""

import logging
import sys

from slither import Slither

from analyze.analyze import basic_vuln
from detectors.gas_opt_detect import GasOptimizationDetector
from parsers.shallow import SecurityScoreParser

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_gas_detector.py <solidity_file>")
        sys.exit(1)

    solidity_file = sys.argv[1]

    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("GasOptimizationDetector")

    # Initialize Slither
    try:
        slither_instance = Slither(solidity_file)
        basics = basic_vuln(solidity_file)
        # The first compilation unit is what we need
        compilation_unit = slither_instance.compilation_units[0]
        # Create and register the detector
        detector = GasOptimizationDetector(compilation_unit, slither_instance, logger)

        # Run the detector with error handling
        try:
            results = detector.detect()

            # Print results
            print("\n=== Gas Optimization Report ===\n")

            print(f"Score for Vuln")
            print("="*100)
            ssp = SecurityScoreParser()
            print(ssp.get_json_report(basics, results))
            
        except Exception as e:
            print(f"Error in detector analysis: {str(e)}")
            import traceback

            traceback.print_exc()
    
    except Exception as e:
        print(f"Error initializing Slither: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
