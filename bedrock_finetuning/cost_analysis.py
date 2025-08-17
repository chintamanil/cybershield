"""
Cost Analysis for Bedrock Fine-tuning in CyberShield
Compares costs and ROI of custom vs base models
"""

from dataclasses import dataclass
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

@dataclass
class ModelCostMetrics:
    """Cost metrics for Bedrock models"""
    input_tokens_per_1m: float
    output_tokens_per_1m: float
    training_cost_per_hour: float = 0.0
    monthly_usage_tokens_input: int = 0
    monthly_usage_tokens_output: int = 0

class BedrockCostAnalyzer:
    """Analyzes costs for Bedrock fine-tuning in CyberShield"""
    
    def __init__(self):
        # Current Bedrock pricing (as of 2024)
        self.model_costs = {
            "claude-3-haiku": ModelCostMetrics(
                input_tokens_per_1m=0.25,
                output_tokens_per_1m=1.25,
                training_cost_per_hour=0.0  # Fine-tuning pricing TBD
            ),
            "claude-3-sonnet": ModelCostMetrics(
                input_tokens_per_1m=3.00,
                output_tokens_per_1m=15.00
            ),
            "titan-text-express": ModelCostMetrics(
                input_tokens_per_1m=0.8,
                output_tokens_per_1m=1.6,
                training_cost_per_hour=1.5  # Estimated
            ),
            "llama2-13b": ModelCostMetrics(
                input_tokens_per_1m=0.75,
                output_tokens_per_1m=1.0,
                training_cost_per_hour=2.0  # Estimated
            )
        }
        
    def calculate_current_cybershield_usage(self) -> Dict[str, int]:
        """Estimate current CyberShield token usage"""
        
        # Based on CyberShield architecture analysis
        monthly_estimates = {
            "react_workflow": {
                "input_tokens": 2_000_000,   # ReAct reasoning chains
                "output_tokens": 500_000     # Tool selection and routing
            },
            "threat_analysis": {
                "input_tokens": 1_500_000,   # IOC processing
                "output_tokens": 400_000     # Threat assessments
            },
            "log_parsing": {
                "input_tokens": 1_000_000,   # Log entries
                "output_tokens": 300_000     # Structured outputs
            },
            "ioc_extraction": {
                "input_tokens": 800_000,     # Text analysis
                "output_tokens": 200_000     # IOC lists
            }
        }
        
        total_input = sum(usage["input_tokens"] for usage in monthly_estimates.values())
        total_output = sum(usage["output_tokens"] for usage in monthly_estimates.values())
        
        return {
            "total_input_tokens": total_input,    # ~5.3M tokens/month
            "total_output_tokens": total_output,  # ~1.4M tokens/month
            "breakdown": monthly_estimates
        }

    def calculate_base_model_costs(self, model_name: str) -> Dict[str, float]:
        """Calculate costs for using base models"""
        
        usage = self.calculate_current_cybershield_usage()
        costs = self.model_costs[model_name]
        
        input_cost = (usage["total_input_tokens"] / 1_000_000) * costs.input_tokens_per_1m
        output_cost = (usage["total_output_tokens"] / 1_000_000) * costs.output_tokens_per_1m
        
        return {
            "monthly_input_cost": input_cost,
            "monthly_output_cost": output_cost,
            "total_monthly_cost": input_cost + output_cost
        }

    def estimate_fine_tuning_costs(self, model_name: str, training_examples: int) -> Dict[str, float]:
        """Estimate fine-tuning costs"""
        
        costs = self.model_costs[model_name]
        
        # Estimate training time based on dataset size
        estimated_training_hours = max(2, training_examples / 500)  # Rough estimate
        
        # Fine-tuning costs (estimated)
        if model_name == "claude-3-haiku":
            # Claude fine-tuning pricing not yet public, using estimates
            training_cost = estimated_training_hours * 5.0  # $5/hour estimate
        else:
            training_cost = estimated_training_hours * costs.training_cost_per_hour
        
        return {
            "estimated_training_hours": estimated_training_hours,
            "one_time_training_cost": training_cost,
            "dataset_preparation_cost": 50.0,  # One-time setup
            "total_fine_tuning_cost": training_cost + 50.0
        }

    def calculate_fine_tuned_model_benefits(self, model_name: str) -> Dict[str, Any]:
        """Calculate potential benefits of fine-tuned models"""
        
        base_costs = self.calculate_base_model_costs(model_name)
        
        # Estimated improvements from fine-tuning
        improvements = {
            "response_quality": 0.25,      # 25% better accuracy
            "token_efficiency": 0.15,      # 15% fewer tokens needed
            "task_specificity": 0.30,      # 30% better at cybersecurity tasks
            "false_positive_reduction": 0.20  # 20% fewer false positives
        }
        
        # Calculate cost savings from token efficiency
        efficient_input_tokens = base_costs["monthly_input_cost"] * (1 - improvements["token_efficiency"])
        efficient_output_tokens = base_costs["monthly_output_cost"] * (1 - improvements["token_efficiency"])
        
        monthly_savings = base_costs["total_monthly_cost"] - (efficient_input_tokens + efficient_output_tokens)
        
        # Calculate operational savings
        operational_savings = {
            "reduced_manual_review": 500.0,    # $500/month from fewer false positives
            "faster_threat_detection": 300.0,  # $300/month from improved accuracy
            "reduced_analyst_time": 800.0      # $800/month from better automation
        }
        
        total_operational_savings = sum(operational_savings.values())
        
        return {
            "token_cost_savings": monthly_savings,
            "operational_savings": operational_savings,
            "total_monthly_savings": monthly_savings + total_operational_savings,
            "improvements": improvements
        }

    def calculate_roi_analysis(self, model_name: str, training_examples: int) -> Dict[str, Any]:
        """Calculate ROI for fine-tuning investment"""
        
        fine_tuning_costs = self.estimate_fine_tuning_costs(model_name, training_examples)
        benefits = self.calculate_fine_tuned_model_benefits(model_name)
        base_costs = self.calculate_base_model_costs(model_name)
        
        # Calculate payback period
        initial_investment = fine_tuning_costs["total_fine_tuning_cost"]
        monthly_savings = benefits["total_monthly_savings"]
        
        payback_months = initial_investment / monthly_savings if monthly_savings > 0 else float('inf')
        
        # Calculate 12-month ROI
        twelve_month_savings = monthly_savings * 12
        roi_12_months = ((twelve_month_savings - initial_investment) / initial_investment) * 100
        
        return {
            "initial_investment": initial_investment,
            "monthly_savings": monthly_savings,
            "payback_period_months": payback_months,
            "roi_12_months_percent": roi_12_months,
            "net_benefit_12_months": twelve_month_savings - initial_investment,
            "break_even_month": payback_months,
            "recommendation": self._get_recommendation(payback_months, roi_12_months)
        }

    def _get_recommendation(self, payback_months: float, roi_12_months: float) -> str:
        """Get recommendation based on ROI analysis"""
        
        if payback_months <= 3 and roi_12_months > 200:
            return "HIGHLY RECOMMENDED - Excellent ROI and quick payback"
        elif payback_months <= 6 and roi_12_months > 100:
            return "RECOMMENDED - Good ROI with reasonable payback period"
        elif payback_months <= 12 and roi_12_months > 50:
            return "CONSIDER - Positive ROI but longer payback period"
        else:
            return "NOT RECOMMENDED - Poor ROI or extended payback period"

    def compare_all_models(self, training_examples: int = 1000) -> Dict[str, Any]:
        """Compare all models for CyberShield use case"""
        
        comparison = {}
        
        for model_name in self.model_costs.keys():
            if model_name == "claude-3-sonnet":  # Skip expensive base model
                continue
                
            base_costs = self.calculate_base_model_costs(model_name)
            roi_analysis = self.calculate_roi_analysis(model_name, training_examples)
            
            comparison[model_name] = {
                "base_monthly_cost": base_costs["total_monthly_cost"],
                "fine_tuning_investment": roi_analysis["initial_investment"],
                "monthly_savings": roi_analysis["monthly_savings"],
                "payback_months": roi_analysis["payback_period_months"],
                "roi_12_months": roi_analysis["roi_12_months_percent"],
                "recommendation": roi_analysis["recommendation"]
            }
        
        # Find best option
        best_model = min(comparison.keys(), 
                        key=lambda k: comparison[k]["payback_months"])
        
        return {
            "comparison": comparison,
            "recommended_model": best_model,
            "summary": self._create_summary(comparison, best_model)
        }

    def _create_summary(self, comparison: Dict[str, Any], best_model: str) -> str:
        """Create executive summary"""
        
        best = comparison[best_model]
        
        return f"""
CyberShield Bedrock Fine-tuning ROI Analysis

RECOMMENDED MODEL: {best_model.upper()}
- Initial Investment: ${best['fine_tuning_investment']:.2f}
- Monthly Savings: ${best['monthly_savings']:.2f}
- Payback Period: {best['payback_months']:.1f} months
- 12-Month ROI: {best['roi_12_months']:.1f}%

KEY BENEFITS:
- 15% reduction in token usage through optimization
- 25% improvement in threat detection accuracy  
- 20% fewer false positives requiring manual review
- $1,600/month operational savings from automation

NEXT STEPS:
1. Prepare training dataset ({1000} cybersecurity examples)
2. Begin fine-tuning with {best_model}
3. A/B test against current OpenAI implementation
4. Full deployment after validation
"""

# Usage example
def main():
    """Generate cost analysis report"""
    
    analyzer = BedrockCostAnalyzer()
    
    print("=== CyberShield Bedrock Fine-tuning Cost Analysis ===\n")
    
    # Current usage analysis
    usage = analyzer.calculate_current_cybershield_usage()
    print(f"Current Monthly Token Usage:")
    print(f"  Input Tokens: {usage['total_input_tokens']:,}")
    print(f"  Output Tokens: {usage['total_output_tokens']:,}\n")
    
    # Base model costs
    print("Base Model Monthly Costs:")
    for model in ["claude-3-haiku", "titan-text-express", "llama2-13b"]:
        costs = analyzer.calculate_base_model_costs(model)
        print(f"  {model}: ${costs['total_monthly_cost']:.2f}")
    print()
    
    # ROI analysis
    comparison = analyzer.compare_all_models(training_examples=1000)
    print("Fine-tuning ROI Comparison:")
    for model, metrics in comparison["comparison"].items():
        print(f"\n{model.upper()}:")
        print(f"  Payback Period: {metrics['payback_months']:.1f} months")
        print(f"  12-Month ROI: {metrics['roi_12_months']:.1f}%")
        print(f"  Recommendation: {metrics['recommendation']}")
    
    print(f"\n{comparison['summary']}")

if __name__ == "__main__":
    main()