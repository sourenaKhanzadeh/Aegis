from slither.slither import Slither
import solc_select.solc_select as solc

# Ensure correct Solidity version
solc.switch_global_version("0.8.20", always_install=True)

# Path to Solidity contract
def basic_vuln(contract_path:str = "contracts/vul.sol"):

    try:
        # Initialize Slither analysis
        slither = Slither(contract_path)

        # Run all Slither detectors
        slither.run_detectors()

        findings = []

        # ✅ Extract vulnerabilities from **ALL** Slither's built-in detectors
        for detector in slither.detectors:
            for issue in detector.issues:
                filename = issue.source_mapping[0].filename.absolute
                line_number = issue.source_mapping[0].lines[0] if issue.source_mapping[0].lines else "Unknown"

                findings.append({
                    "vulnerability": issue.check,
                    "description": issue.description,
                    "severity": issue.impact,
                    "locations": [f"{filename}:{line_number}"]
                })

        # ✅ Manually check for additional vulnerabilities (not all are covered by detectors)
        for contract in slither.contracts:
            for function in contract.functions_entry_points:
                line_info = None
                # Check if source_mapping exists before accessing it
                if hasattr(function, 'source_mapping') and function.source_mapping:
                    line_info = f"at line {function.source_mapping}"

                function_location = f"{contract.name}:{function.name} {line_info}"

                # **Reentrancy**
                if function.is_reentrant and function.visibility == "external":
                    findings.append({
                        "vulnerability": "Reentrancy",
                        "description": f"Reentrancy detected in function: {function.name}",
                        "severity": "High",
                        "locations": [function_location]
                    })

                # **Access Control Issues**
                if function.name.lower() in ["changeowner", "setowner"] and function.visibility in ["public", "external"]:
                    findings.append({
                        "vulnerability": "Access Control",
                        "description": f"Potential access control issue in function: {function.name}",
                        "severity": "Medium",
                        "locations": [function_location]
                    })

                # **Weak Randomness**
                for node in function.nodes:
                    if node.expression and "block.timestamp" in str(node.expression):
                        findings.append({
                            "vulnerability": "Weak Randomness",
                            "description": f"Block.timestamp used in function: {function.name}",
                            "severity": "Medium",
                            "locations": [function_location]
                        })

                # **Unchecked Low-Level Calls**
                for node in function.nodes:
                    if node.expression and "call" in str(node.expression) and "require" not in str(node.expression):
                        findings.append({
                            "vulnerability": "Unchecked Low-Level Call",
                            "description": f"Low-level call without require in function: {function.name}",
                            "severity": "High",
                            "locations": [function_location]
                        })

                # **Delegatecall Vulnerabilities**
                for node in function.nodes:
                    if node.expression and "delegatecall" in str(node.expression):
                        findings.append({
                            "vulnerability": "Delegatecall Vulnerability",
                            "description": f"Unsafe delegatecall used in function: {function.name}",
                            "severity": "High",
                            "locations": [function_location]
                        })

                # **Tx-Origin Authentication Issues**
                for node in function.nodes:
                    if node.expression and "tx.origin" in str(node.expression):
                        findings.append({
                            "vulnerability": "Tx-Origin Authentication",
                            "description": f"tx.origin used for authentication in function: {function.name}",
                            "severity": "High",
                            "locations": [function_location]
                        })

                # **Selfdestruct Vulnerabilities**
                for node in function.nodes:
                    if node.expression and "selfdestruct" in str(node.expression):
                        findings.append({
                            "vulnerability": "Selfdestruct Vulnerability",
                            "description": f"Unsafe selfdestruct used in function: {function.name}",
                            "severity": "High",
                            "locations": [function_location]
                        })

                # **Integer Overflows/Underflows**
                for node in function.nodes:
                    if node.expression and ("+" in str(node.expression) or "-" in str(node.expression) or "*" in str(node.expression)):
                        if "SafeMath" not in str(node.expression):
                            findings.append({
                                "vulnerability": "Integer Overflow/Underflow",
                                "description": f"Potential integer overflow/underflow in function: {function.name}",
                                "severity": "High",
                                "locations": [function_location]
                            })

                # **Gas Limit Manipulation**
                for node in function.nodes:
                    if node.expression and "gasleft()" in str(node.expression):
                        findings.append({
                            "vulnerability": "Gas Limit Manipulation",
                            "description": f"gasleft() used in function: {function.name}, can lead to gas manipulation attacks",
                            "severity": "Medium",
                            "locations": [function_location]
                        })

                # **Uninitialized Storage Variables**
                if function.is_shadowed:
                    findings.append({
                        "vulnerability": "Uninitialized Storage Variable",
                        "description": f"Uninitialized storage variable found in function: {function.name}",
                        "severity": "High",
                        "locations": [function_location]
                    })

        # ✅ Print findings
        return findings

    except Exception as e:
        print(f"Error running Slither: {e}")
