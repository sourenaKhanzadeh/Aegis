from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function
from slither.utils.output import Output
from slither.core.compilation_unit import SlitherCompilationUnit
from slither import Slither
from typing import List, Dict, Set, Tuple
from slither.core.declarations.contract import Contract
import logging
from logging import Logger

class GasOptimizationDetector(AbstractDetector):
    """
    Detector for identifying common gas optimization opportunities in Solidity contracts
    """
    
    ARGUMENT = "gas-optimization"  # Unique identifier for the detector
    HELP = "Identifies potential gas optimizations"
    IMPACT = DetectorClassification.OPTIMIZATION  # Level of impact
    CONFIDENCE = DetectorClassification.HIGH  # Confidence in findings
    
    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#gas-optimization"
    WIKI_TITLE = "Gas Optimization"
    WIKI_DESCRIPTION = "Identifies code patterns that could be optimized for gas efficiency."
    WIKI_RECOMMENDATION = "Consider implementing the suggested gas optimizations."
    
    def __init__(
        self, compilation_unit: SlitherCompilationUnit, slither: "Slither", logger: Logger
    ) -> None:
        self.compilation_unit: SlitherCompilationUnit = compilation_unit
        self.contracts: List[Contract] = compilation_unit.contracts
        self.slither: "Slither" = slither
        self.logger = logger
    
    def _detect(self):
        """
        Main detection method for the detector
        Returns:
            List[Output]: List of detected optimization opportunities
        """
        results = []
        
        for contract in self.compilation_unit.contracts:
            # Check storage layouts
            storage_results = self._check_storage_layout(contract)
            if storage_results:
                results.extend(storage_results)

            # Check function-level optimizations
            for function in contract.functions:
                function_results = self._check_function_optimizations(function)
                if function_results:
                    results.extend(function_results)

            # Check loop optimizations
            loop_results = self._check_loop_optimizations(contract)
            if loop_results:
                results.extend(loop_results)
                
        return results
        
    def generate_result(self, info, additional_fields=None):
        """
        Generate a properly formatted result with all required fields
        Args:
            info: The information list describing the result
            additional_fields: Additional fields to add to the result
        """
        # Create a standardized result with recommendation
        if additional_fields is None:
            additional_fields = {}
            
        # Ensure recommendation is present in additional_fields
        if 'recommendation' not in additional_fields:
            additional_fields['recommendation'] = self.WIKI_RECOMMENDATION
            
        # Call the parent class method with the correct parameters
        result = super().generate_result(info, additional_fields)
        return result
    
    def _check_storage_layout(self, contract):
        """
        Check for inefficient storage variable layouts
        """
        results = []
        
        # Get all state variables
        state_vars = contract.state_variables
        
        # Skip if there are fewer than 2 variables (nothing to optimize)
        if len(state_vars) < 2:
            return results
            
        # Group variables by size (uint8, uint16, uint32, etc.)
        size_groups = {
            1: [],  # 1 byte (uint8, bool, etc.)
            2: [],  # 2 bytes (uint16, etc.)
            3: [],  # 3 bytes (uint24, etc.)
            4: [],  # 4 bytes (uint32, etc.)
            32: []  # 32 bytes (uint256, address, etc.)
        }
        
        for var in state_vars:
            if var.type:
                # Determine byte size based on type
                if "uint8" in str(var.type) or "bool" in str(var.type):
                    size_groups[1].append(var)
                elif "uint16" in str(var.type):
                    size_groups[2].append(var)
                elif "uint24" in str(var.type):
                    size_groups[3].append(var)
                elif "uint32" in str(var.type):
                    size_groups[4].append(var)
                elif "address" in str(var.type) or "uint256" in str(var.type):
                    size_groups[32].append(var)
        
        # Check if smaller variables could be packed together
        small_vars = size_groups[1] + size_groups[2] + size_groups[3] + size_groups[4]
        if len(small_vars) >= 2:
            var_names = ", ".join([v.name for v in small_vars])
            
            info = [
                "Storage variables could be packed more efficiently in ",
                contract,
                ":\n"
            ]
            
            for var in small_vars:
                info.extend(["\t- ", var, f" ({var.type})\n"])
                
            info.extend(["\nPacking these variables together can save gas."])
            
            res = self.generate_result(info)
            results.append(res)
            
        return results
    
    def _check_function_optimizations(self, function):
        """
        Check for function-level gas optimizations
        """
        results = []
        
        # Check for public functions that could be external
        if function.visibility == "public" and not function.is_constructor and not function.is_fallback:
            # Check if function is only called externally
            is_called_internally = False
            for contract in self.contracts:
                for potential_caller in contract.functions:
                    # Skip the function itself
                    if potential_caller == function:
                        continue
                    
                    # Check if this function calls our target function
                    for internal_call in potential_caller.internal_calls:
                        if internal_call == function:
                            is_called_internally = True
                            break
                    
                    if is_called_internally:
                        break
                
                if is_called_internally:
                    break
            
            # If the function is not called internally, it could be external
            if not is_called_internally:
                info = [
                    "Function declared as public but could be external: ",
                    function,
                    " in ",
                    function.contract,
                    "\nChanging from public to external can save gas."
                ]
                results.append(self.generate_result(info))
        
        # Check for unnecessary use of memory for function parameters
        for param in function.parameters:
            param_type_str = str(param.type)
            if "[]" in param_type_str and "memory" in param_type_str and function.visibility == "external":
                if "string" not in param_type_str and "bytes" not in param_type_str:
                    info = [
                        "External function parameter uses memory instead of calldata: ",
                        param,
                        " in function ",
                        function,
                        "\nUsing calldata instead of memory for external function parameters can save gas."
                    ]
                    results.append(self.generate_result(info))
        
        # Check for constant/immutable variables that could save gas
        for var_read in function.state_variables_read:
            if not var_read.is_constant and not hasattr(var_read, 'is_immutable'):
                # Check if the variable is never written after deployment
                is_written = False
                for func in function.contract.functions:
                    if func.is_constructor:
                        continue
                    if var_read in func.state_variables_written:
                        is_written = True
                        break
                
                if not is_written:
                    info = [
                        "State variable could be declared immutable: ",
                        var_read,
                        " in contract ",
                        function.contract,
                        "\nUsing immutable for variables that don't change after deployment saves gas."
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _check_loop_optimizations(self, contract):
        """
        Check for loop-related gas optimizations
        """
        results = []
        
        for function in contract.functions:
            # Skip if function has no nodes
            if not function.nodes:
                continue
            
            for node in function.nodes:
                # Check if this is a loop
                if node.type == "STARTLOOP":
                    # Check if there's an array length access in the loop condition
                    if node.expression and ".length" in str(node.expression):
                        info = [
                            "Loop condition contains array length access: ",
                            str(node.expression),
                            " in function ",
                            function,
                            "\nCaching array length outside the loop can save gas."
                        ]
                        results.append(self.generate_result(info))
                    
                    # Look for state variable reads in loop
                    for var_read in node.variables_read:
                        if var_read in contract.state_variables:
                            info = [
                                "State variable read in loop: ",
                                str(var_read),
                                " in function ",
                                function,
                                "\nCaching state variables before loops can save gas."
                            ]
                            results.append(self.generate_result(info))
        
        return results


# To register the detector with Slither, add to the imports in slither/detectors/__init__.py:
# from slither.detectors.gas_optimization.gas_optimization import GasOptimizationDetector
# Then add it to the DETECTORS list in that file
