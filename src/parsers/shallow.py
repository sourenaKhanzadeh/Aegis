import json
import logging
from typing import Any, Dict, List, Optional, Union


class SecurityScoreParser:
    """
    Parser class to convert vulnerability and gas optimization findings into a numerical score.

    The score is calculated out of 100 points, with vulnerabilities reducing the score
    and gas optimizations having a smaller impact.
    """

    # Severity weights for vulnerabilities
    SEVERITY_WEIGHTS = {
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Optimization": 1.5,
        "Informational": 0.5,
        "Unknown": 5,
    }

    # Vulnerability categories that should be prioritized
    CRITICAL_VULNERABILITIES = [
        "Reentrancy",
        "Unchecked Low-Level Call",
        "Delegatecall Vulnerability",
        "Selfdestruct Vulnerability",
        "Integer Overflow/Underflow",
        "Tx-Origin Authentication",
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities = []
        self.gas_optimizations = []
        self.score = 100
        self.breakdown = {
            "base_score": 100,
            "vulnerability_deductions": 0,
            "gas_deductions": 0,
            "critical_vulnerabilities": [],
            "all_vulnerabilities": [],
            "gas_optimizations": [],
        }

    def parse_vulnerabilities(self, findings: List[Dict[str, Any]]) -> None:
        """
        Parse vulnerability findings from the basic vulnerability detector.

        Args:
            findings: List of vulnerability dictionaries
        """
        total_deduction = 0

        for finding in findings:
            try:
                vulnerability = finding.get("vulnerability", "Unknown")
                severity = finding.get("severity", "Unknown")
                description = finding.get("description", "No description provided")
                locations = finding.get("locations", ["Unknown location"])

                # Calculate deduction based on severity
                deduction = self.SEVERITY_WEIGHTS.get(
                    severity, self.SEVERITY_WEIGHTS["Unknown"]
                )

                # Apply extra penalty for critical vulnerabilities
                if vulnerability in self.CRITICAL_VULNERABILITIES:
                    deduction *= 1.5
                    self.breakdown["critical_vulnerabilities"].append(
                        {
                            "vulnerability": vulnerability,
                            "severity": severity,
                            "deduction": deduction,
                            "description": description,
                            "locations": locations,
                        }
                    )

                # Track all vulnerabilities
                self.vulnerabilities.append(
                    {
                        "vulnerability": vulnerability,
                        "severity": severity,
                        "deduction": deduction,
                        "description": description,
                        "locations": locations,
                    }
                )

                self.breakdown["all_vulnerabilities"].append(
                    {
                        "vulnerability": vulnerability,
                        "severity": severity,
                        "deduction": deduction,
                        "description": description,
                        "locations": locations,
                    }
                )

                total_deduction += deduction

            except Exception as e:
                self.logger.error(f"Error processing vulnerability: {e}")

        # Apply vulnerability deductions with a cap
        self.breakdown["vulnerability_deductions"] = min(total_deduction, 80)
        self.score -= self.breakdown["vulnerability_deductions"]

    def parse_gas_optimizations(self, findings: List[Dict[str, Any]]) -> None:
        """
        Parse gas optimization findings from the gas optimization detector.

        Args:
            findings: List of gas optimization dictionaries
        """
        # Maximum deduction for gas optimizations is 20 points
        total_deduction = 0
        max_gas_deduction = 20

        for finding in findings:
            try:
                description = finding.get("description", "No description provided")
                location = finding.get("location", "Unknown location")
                recommendation = finding.get(
                    "recommendation", "No recommendation provided"
                )

                # Each gas optimization finding deducts 1.5 points
                deduction = self.SEVERITY_WEIGHTS["Optimization"]

                self.gas_optimizations.append(
                    {
                        "description": description,
                        "location": location,
                        "recommendation": recommendation,
                        "deduction": deduction,
                    }
                )

                self.breakdown["gas_optimizations"].append(
                    {
                        "description": description,
                        "location": location,
                        "recommendation": recommendation,
                        "deduction": deduction,
                    }
                )

                total_deduction += deduction

            except Exception as e:
                self.logger.error(f"Error processing gas optimization: {e}")

        # Calculate gas optimization deduction with a cap
        gas_deduction = min(total_deduction, max_gas_deduction)
        # Scale down based on number of findings to prevent excessive penalties
        if len(findings) > 0:
            scaled_deduction = gas_deduction * (1 - (0.7 / len(findings)))
        else:
            scaled_deduction = 0

        self.breakdown["gas_deductions"] = scaled_deduction
        self.score -= scaled_deduction

    def calculate_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        gas_optimizations: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Calculate the final security score based on vulnerabilities and gas optimizations.

        Args:
            vulnerabilities: List of vulnerability findings
            gas_optimizations: List of gas optimization findings

        Returns:
            Dictionary with score and breakdown details
        """
        # Reset score for new calculation
        self.score = 100
        self.breakdown = {
            "base_score": 100,
            "vulnerability_deductions": 0,
            "gas_deductions": 0,
            "critical_vulnerabilities": [],
            "all_vulnerabilities": [],
            "gas_optimizations": [],
        }

        # Parse findings
        self.parse_vulnerabilities(vulnerabilities)
        self.parse_gas_optimizations(gas_optimizations)

        # Ensure score is between 0 and 100
        self.score = max(0, min(100, self.score))

        # Determine grade based on score
        grade = self._get_grade(self.score)

        return {
            "score": round(self.score, 1),
            "grade": grade,
            "breakdown": self.breakdown,
            "vulnerability_count": len(self.vulnerabilities),
            "gas_optimization_count": len(self.gas_optimizations),
            "critical_vulnerability_count": len(
                self.breakdown["critical_vulnerabilities"]
            ),
        }

    def _get_grade(self, score: float) -> str:
        """
        Convert numerical score to letter grade.

        Args:
            score: Numerical score (0-100)

        Returns:
            Letter grade (A+, A, B, C, D, F)
        """
        if score >= 97:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def get_json_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        gas_optimizations: List[Dict[str, Any]],
    ) -> str:
        """
        Generate a JSON report with score and detailed breakdown.

        Args:
            vulnerabilities: List of vulnerability findings
            gas_optimizations: List of gas optimization findings

        Returns:
            JSON string with complete report
        """
        result = self.calculate_score(vulnerabilities, gas_optimizations)
        return json.dumps(result, indent=2)

    def print_report_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        gas_optimizations: List[Dict[str, Any]],
    ) -> None:
        """
        Print a human-readable summary of the security score.

        Args:
            vulnerabilities: List of vulnerability findings
            gas_optimizations: List of gas optimization findings
        """
        result = self.calculate_score(vulnerabilities, gas_optimizations)

        print("\n===== SMART CONTRACT SECURITY SCORE =====")
        print(f"Score: {result['score']}/100 (Grade: {result['grade']})")
        print(
            f"Vulnerabilities: {result['vulnerability_count']} (Critical: {result['critical_vulnerability_count']})"
        )
        print(f"Gas Optimizations: {result['gas_optimization_count']}")

        if result["critical_vulnerability_count"] > 0:
            print("\nCritical Vulnerabilities:")
            for vuln in self.breakdown["critical_vulnerabilities"]:
                print(f"  - {vuln['vulnerability']} ({vuln['severity']})")
                print(f"    Location: {', '.join(vuln['locations'])}")

        print("\nDeductions Breakdown:")
        print(
            f"  - Vulnerability deductions: -{self.breakdown['vulnerability_deductions']:.1f}"
        )
        print(
            f"  - Gas optimization deductions: -{self.breakdown['gas_deductions']:.1f}"
        )
